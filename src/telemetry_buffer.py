import os
import re
import glob
import time
import json
import asyncio
import logging
import sqlite3
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.responses import JSONResponse

# Optional PyYAML support with JSON fallback
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False

# =========================================================
# Logging Configuration
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SentinelDetection] %(message)s"
)
logger = logging.getLogger("NomadikTelemetry")

# =========================================================
# Data Models
# =========================================================
class SecurityEvent(BaseModel):
    event_id: str = Field(..., description="Unique client-generated event UUID")
    source_ip: str
    host_identifier: str
    event_type: str = Field(..., description="e.g., sysmon_process_create, dns_query, auth_failure")
    severity: str = Field("INFO", description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    payload: Dict[str, Any]
    timestamp: float = Field(default_factory=time.time)

class TelemetryBatch(BaseModel):
    batch_id: str
    agent_version: str
    events: List[SecurityEvent]

# =========================================================
# Dynamic Sigma Threat Detection Engine
# =========================================================
class SigmaRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        mitre_tag: str,
        event_type: str,
        field_matches: Optional[Dict[str, List[str]]] = None,
        regex_matches: Optional[Dict[str, str]] = None,
        source_file: str = "builtin"
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity.upper()
        self.mitre_tag = mitre_tag
        self.event_type = event_type
        self.field_matches = field_matches or {}
        self.regex_matches = {k: re.compile(v, re.IGNORECASE) for k, v in (regex_matches or {}).items()}
        self.source_file = source_file

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if self.event_type != "*" and event.get("event_type") != self.event_type:
            return False

        payload = event.get("payload", {})
        
        # 1. Substring keyword evaluation
        for field, keywords in self.field_matches.items():
            field_val = str(payload.get(field, "")).lower()
            if not any(kw.lower() in field_val for kw in keywords):
                return False

        # 2. Regular expression evaluation
        for field, regex in self.regex_matches.items():
            field_val = str(payload.get(field, ""))
            if not regex.search(field_val):
                return False

        return True


class DynamicSigmaEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules: List[SigmaRule] = []
        self.reload_rules()

    def reload_rules(self) -> int:
        """Loads default built-in rules and all external YAML/JSON rules from rules/ directory."""
        new_rules: List[SigmaRule] = []
        
        # 1. Built-in Core Rule Fallbacks
        new_rules.extend([
            SigmaRule(
                rule_id="SIGMA-001",
                title="Credential Dumping via Memory Extraction (Mimikatz/LSA)",
                severity="CRITICAL",
                mitre_tag="T1003.001",
                event_type="sysmon_process_create",
                field_matches={
                    "command_line": ["sekurlsa::logonpasswords", "privilege::debug", "token::elevate", "lsadump::sam"]
                },
                source_file="builtin"
            ),
            SigmaRule(
                rule_id="SIGMA-002",
                title="Obfuscated / Bypassed PowerShell Execution",
                severity="HIGH",
                mitre_tag="T1059.001",
                event_type="sysmon_process_create",
                field_matches={
                    "process": ["powershell.exe", "pwsh.exe"]
                },
                regex_matches={
                    "command_line": r"(-enc|-encodedcommand|-nop|-noprofile|-w\s+hidden|-exec\s+bypass)"
                },
                source_file="builtin"
            ),
            SigmaRule(
                rule_id="SIGMA-003",
                title="Suspicious C2 Domain Telemetry Lookup",
                severity="HIGH",
                mitre_tag="T1071.004",
                event_type="dns_query",
                regex_matches={
                    "query_domain": r"(c2\.|payload\.|exfil\.|temp-tunnel\.|ngrok\.io|webhook\.site)"
                },
                source_file="builtin"
            )
        ])

        # 2. Dynamically Load YAML and JSON rules from rules/ directory
        if os.path.exists(self.rules_dir):
            file_patterns = [
                os.path.join(self.rules_dir, "**/*.yml"),
                os.path.join(self.rules_dir, "**/*.yaml"),
                os.path.join(self.rules_dir, "**/*.json")
            ]
            found_files = []
            for pattern in file_patterns:
                found_files.extend(glob.glob(pattern, recursive=True))

            for file_path in found_files:
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        if file_path.endswith((".yml", ".yaml")):
                            if not YAML_AVAILABLE:
                                logger.warning(f"[!] PyYAML not installed. Skipping YAML rule: {file_path}")
                                continue
                            data = yaml.safe_load(f)
                        else:
                            data = json.load(f)

                    if not isinstance(data, dict):
                        continue

                    # Handle list of rules or single rule structure
                    rule_items = data.get("rules", [data]) if "rules" in data else [data]
                    for item in rule_items:
                        if "rule_id" in item and "title" in item and "event_type" in item:
                            new_rules.append(
                                SigmaRule(
                                    rule_id=str(item["rule_id"]),
                                    title=str(item["title"]),
                                    severity=str(item.get("severity", "MEDIUM")),
                                    mitre_tag=str(item.get("mitre_tag", "UNKNOWN")),
                                    event_type=str(item["event_type"]),
                                    field_matches=item.get("field_matches", {}),
                                    regex_matches=item.get("regex_matches", {}),
                                    source_file=os.path.basename(file_path)
                                )
                            )
                except Exception as e:
                    logger.error(f"[!] Failed to parse rule definition in {file_path}: {e}")

        # Deduplicate rules by rule_id (file rules override builtins)
        dedup_rules: Dict[str, SigmaRule] = {}
        for r in new_rules:
            dedup_rules[r.rule_id] = r

        self.rules = list(dedup_rules.values())
        logger.info(f"[✓] Dynamic Sigma Engine initialized: {len(self.rules)} active rules loaded.")
        return len(self.rules)

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        for rule in self.rules:
            if rule.evaluate(event):
                matches.append({
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "mitre_tag": rule.mitre_tag,
                    "source_file": rule.source_file
                })
        return matches

# =========================================================
# Async Database Persistence Layer
# =========================================================
class AsyncTelemetryStore:
    def __init__(self, db_path: str = "data/telemetry_events.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    batch_id TEXT,
                    agent_version TEXT,
                    source_ip TEXT,
                    host_identifier TEXT,
                    event_type TEXT,
                    severity TEXT,
                    payload TEXT,
                    matched_rules TEXT,
                    event_timestamp REAL,
                    received_at REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    event_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_tag TEXT NOT NULL,
                    host_identifier TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(event_id) REFERENCES telemetry_events(event_id)
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_event_id ON telemetry_events(event_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_host ON telemetry_events(host_identifier);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_severity ON telemetry_events(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON security_alerts(rule_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);")
            conn.commit()

    def _sync_insert_batch_and_alerts(self, batch: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> int:
        records = [
            (
                ev["event_id"],
                ev.get("batch_id"),
                ev.get("agent_version"),
                ev["source_ip"],
                ev["host_identifier"],
                ev["event_type"],
                ev["severity"],
                json.dumps(ev.get("payload", {})),
                json.dumps(ev.get("matched_rules", [])),
                ev.get("timestamp", time.time()),
                ev.get("received_at", time.time())
            )
            for ev in batch
        ]

        alert_records = [
            (
                al["alert_id"],
                al["event_id"],
                al["rule_id"],
                al["title"],
                al["severity"],
                al["mitre_tag"],
                al["host_identifier"],
                al["source_ip"],
                json.dumps(al.get("details", {}))
            )
            for al in alerts
        ]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO telemetry_events (
                    event_id, batch_id, agent_version, source_ip, host_identifier,
                    event_type, severity, payload, matched_rules, event_timestamp, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    payload=excluded.payload,
                    severity=excluded.severity,
                    matched_rules=excluded.matched_rules,
                    received_at=excluded.received_at;
            """, records)

            if alert_records:
                cursor.executemany("""
                    INSERT INTO security_alerts (
                        alert_id, event_id, rule_id, title, severity, mitre_tag,
                        host_identifier, source_ip, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO NOTHING;
                """, alert_records)

            conn.commit()
            return cursor.rowcount

    def _sync_get_metrics(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM telemetry_events;")
            total_events = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM security_alerts;")
            total_alerts = cursor.fetchone()[0]
            return {"total_events": total_events, "total_alerts": total_alerts}

    def _sync_get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, alert_id, event_id, rule_id, title, severity, mitre_tag,
                       host_identifier, source_ip, details, created_at
                FROM security_alerts
                ORDER BY id DESC
                LIMIT ?;
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                try:
                    item["details"] = json.loads(item["details"])
                except Exception:
                    pass
                results.append(item)
            return results

    async def insert_batch_and_alerts(self, batch: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> int:
        return await asyncio.to_thread(self._sync_insert_batch_and_alerts, batch, alerts)

    async def get_metrics(self) -> Dict[str, int]:
        return await asyncio.to_thread(self._sync_get_metrics)

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync_get_recent_alerts, limit)

# =========================================================
# High-Throughput Buffer Queue & Consumer
# =========================================================
class TelemetryStreamBuffer:
    def __init__(self, db_store: AsyncTelemetryStore, sigma_engine: DynamicSigmaEngine, max_buffer_size: int = 50000, batch_window_ms: int = 100, batch_size: int = 500):
        self.db_store = db_store
        self.sigma_engine = sigma_engine
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_buffer_size)
        self.dlq: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.batch_window_sec = batch_window_ms / 1000.0
        self.batch_size = batch_size
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    async def push(self, event: Dict[str, Any]) -> bool:
        try:
            self.queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            logger.warning("[!] Ingestion buffer queue full. Applying backpressure.")
            return False

    async def push_batch(self, events: List[Dict[str, Any]]) -> int:
        accepted = 0
        for ev in events:
            if await self.push(ev):
                accepted += 1
            else:
                break
        return accepted

    async def start_worker(self):
        self._running = True
        self._worker_task = asyncio.create_task(self._consumer_loop())
        logger.info(f"[✓] Micro-batch consumer loop started (Window: {self.batch_window_sec*1000}ms, Max Batch: {self.batch_size})")

    async def stop_worker(self):
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("[✓] Micro-batch worker terminated cleanly.")

    async def _consumer_loop(self):
        while self._running:
            batch: List[Dict[str, Any]] = []
            start_time = time.monotonic()

            while len(batch) < self.batch_size:
                timeout = max(0.0, self.batch_window_sec - (time.monotonic() - start_time))
                try:
                    event = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                    batch.append(event)
                    self.queue.task_done()
                except asyncio.TimeoutError:
                    break

            if batch:
                await self._process_batch(batch)

    async def _process_batch(self, batch: List[Dict[str, Any]]):
        t0 = time.perf_counter()
        generated_alerts: List[Dict[str, Any]] = []

        # 1. Run Dynamic Sigma Rule Matching
        for event in batch:
            matches = self.sigma_engine.evaluate_event(event)
            if matches:
                event["matched_rules"] = matches
                severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                highest_sev = max(matches, key=lambda m: severities.index(m["severity"]) if m["severity"] in severities else 0)["severity"]
                if severities.index(highest_sev) > severities.index(event.get("severity", "INFO")):
                    event["severity"] = highest_sev

                for match in matches:
                    alert_id = f"ALT-{event['event_id'][:8]}-{match['rule_id']}"
                    alert = {
                        "alert_id": alert_id,
                        "event_id": event["event_id"],
                        "rule_id": match["rule_id"],
                        "title": match["title"],
                        "severity": match["severity"],
                        "mitre_tag": match["mitre_tag"],
                        "host_identifier": event["host_identifier"],
                        "source_ip": event["source_ip"],
                        "details": event.get("payload", {})
                    }
                    generated_alerts.append(alert)
                    logger.warning(f"🚨 [DETECTION TRIGGERED] {match['rule_id']} ({match['severity']}) - {match['title']} on {event['host_identifier']} [source: {match['source_file']}]")

        # 2. Persist Telemetry Batch & Alerts to DB
        try:
            inserted_count = await self.db_store.insert_batch_and_alerts(batch, generated_alerts)
            latency_ms = (time.perf_counter() - t0) * 1000
            logger.info(f"Persisted {inserted_count} events ({len(generated_alerts)} alerts) in {latency_ms:.2f}ms | Buffer depth: {self.queue.qsize()}")
        except Exception as e:
            logger.error(f"[!] Batch persistence failure: {e}. Diverting events to DLQ.")
            for failed_ev in batch:
                try:
                    self.dlq.put_nowait(failed_ev)
                except asyncio.QueueFull:
                    pass

# =========================================================
# FastAPI Application & Endpoints
# =========================================================
db_store = AsyncTelemetryStore()
sigma_engine = DynamicSigmaEngine(rules_dir="rules")
buffer_engine = TelemetryStreamBuffer(db_store=db_store, sigma_engine=sigma_engine)

app = FastAPI(
    title="Nomadik Security Sentinel - Telemetry Engine",
    version="2.3.0"
)

@app.on_event("startup")
async def startup_event():
    await buffer_engine.start_worker()

@app.on_event("shutdown")
async def shutdown_event():
    await buffer_engine.stop_worker()

@app.post("/api/v1/telemetry/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: SecurityEvent):
    event_dict = event.dict()
    event_dict["received_at"] = time.time()
    
    accepted = await buffer_engine.push(event_dict)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion buffer saturated. Retry with backpressure."
        )
    return {"status": "buffered", "event_id": event.event_id}

@app.post("/api/v1/telemetry/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_stream(batch: TelemetryBatch):
    raw_events = [ev.dict() for ev in batch.events]
    now = time.time()
    for ev in raw_events:
        ev["received_at"] = now
        ev["batch_id"] = batch.batch_id
        ev["agent_version"] = batch.agent_version

    accepted_count = await buffer_engine.push_batch(raw_events)
    
    if accepted_count < len(raw_events):
        return JSONResponse(
            status_code=status.HTTP_207_MULTI_STATUS,
            content={
                "status": "partial_success",
                "accepted": accepted_count,
                "rejected": len(raw_events) - accepted_count,
                "detail": "Buffer threshold reached."
            }
        )

    return {
        "status": "buffered",
        "batch_id": batch.batch_id,
        "count": accepted_count
    }

@app.get("/api/v1/telemetry/health")
async def telemetry_health():
    metrics = await db_store.get_metrics()
    return {
        "status": "healthy",
        "buffer_depth": buffer_engine.queue.qsize(),
        "dlq_depth": buffer_engine.dlq.qsize(),
        "max_capacity": buffer_engine.queue.maxsize,
        "persisted_events": metrics["total_events"],
        "security_alerts_count": metrics["total_alerts"]
    }

@app.get("/api/v1/telemetry/alerts")
async def get_security_alerts(limit: int = Query(25, ge=1, le=500)):
    alerts = await db_store.get_recent_alerts(limit=limit)
    return {
        "count": len(alerts),
        "alerts": alerts
    }

@app.get("/api/v1/telemetry/rules")
async def get_active_rules():
    return {
        "total_rules": len(sigma_engine.rules),
        "rules_directory": sigma_engine.rules_dir,
        "rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity,
                "mitre_tag": r.mitre_tag,
                "event_type": r.event_type,
                "source_file": r.source_file
            }
            for r in sigma_engine.rules
        ]
    }

@app.post("/api/v1/telemetry/rules/reload")
async def reload_sigma_rules():
    count = sigma_engine.reload_rules()
    return {
        "status": "reloaded",
        "total_rules_active": count,
        "rules_directory": sigma_engine.rules_dir
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.telemetry_buffer:app", host="0.0.0.0", port=8080, reload=True)
