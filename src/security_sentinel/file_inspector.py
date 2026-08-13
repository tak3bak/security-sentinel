import os, re, math, uuid, json, shutil, hashlib, logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from security_sentinel.edr_threat_rules import EDRThreatEngine, ThreatAlert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FileInspector")

SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "AWS_ACCESS_KEY_ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS_SECRET_ACCESS_KEY": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "GITHUB_TOKEN": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "OPENAI_API_KEY": re.compile(r"\bsk-(proj-)?[a-zA-Z0-9_\-]{32,}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----"),
    "GENERIC_SECRET_ASSIGNMENT": re.compile(r"(?i)(password|secret_key|api_key|access_token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
}

def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return round(entropy, 4)

class QuarantineManager:
    def __init__(self, quarantine_dir: str = "quarantine"):
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, file_path: str, rule_matched: str, entropy: float, alert_details: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if not os.path.exists(file_path): return None
        now = datetime.utcnow()
        date_path = os.path.join(self.quarantine_dir, now.strftime("%Y"), now.strftime("%m"), now.strftime("%d"))
        os.makedirs(date_path, exist_ok=True)
        dest_path = os.path.join(date_path, f"{str(uuid.uuid4())[:8]}_{os.path.basename(file_path)}")

        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""): sha256.update(chunk)
            shutil.move(file_path, dest_path)
            logger.info(f"Quarantined {file_path} -> {dest_path}")
            with open(f"{dest_path}.json", "w", encoding="utf-8") as meta_f:
                json.dump({
                    "original_path": os.path.abspath(file_path), "quarantined_path": dest_path,
                    "sha256": sha256.hexdigest(), "detected_rule": rule_matched, "entropy_score": entropy,
                    "timestamp": now.isoformat() + "Z", "alert_details": alert_details
                }, meta_f, indent=2)
            return dest_path
        except Exception as e:
            logger.error(f"Quarantine error: {e}")
            return None

class FileInspector:
    def __init__(self, quarantine_dir: str = "quarantine", entropy_threshold: float = 4.5, manifest_path: Optional[str] = "rules/edr_threat_rules.json"):
        self.quarantine_mgr = QuarantineManager(quarantine_dir)
        self.entropy_threshold = entropy_threshold
        self.edr_engine = EDRThreatEngine(manifest_path if os.path.exists(manifest_path or "") else None)

    def inspect_file(self, file_path: str) -> Dict[str, Any]:
        result = {"file_path": file_path, "is_clean": True, "rule_matched": None, "entropy": 0.0, "quarantined_to": None, "edr_alerts": []}
        if not os.path.isfile(file_path) or os.path.abspath(file_path).startswith(self.quarantine_mgr.quarantine_dir):
            return result

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f: content = f.read()
        except Exception: return result

        # 1. EDR JSON Log check
        if file_path.endswith(".json") or content.strip().startswith("{"):
            try:
                data = json.loads(content)
                events = data if isinstance(data, list) else [data]
                for evt in events:
                    if isinstance(evt, dict):
                        alerts = self.edr_engine.process_event(evt)
                        if alerts:
                            top = alerts[0]
                            q = self.quarantine_mgr.quarantine_file(file_path, top.rule_id, 0.0, top.dict())
                            result.update({"is_clean": False, "rule_matched": top.rule_id, "quarantined_to": q, "edr_alerts": [a.dict() for a in alerts]})
                            return result
            except json.JSONDecodeError: pass

        # 2. Secret signatures
        for rule_name, pat in SECRET_PATTERNS.items():
            m = pat.search(content)
            if m:
                ent = calculate_shannon_entropy(m.group(0))
                q = self.quarantine_mgr.quarantine_file(file_path, rule_name, ent)
                result.update({"is_clean": False, "rule_matched": rule_name, "entropy": ent, "quarantined_to": q})
                return result

        # 3. High entropy tokens
        for token in re.findall(r"\b[A-Za-z0-9/+=_-]{20,}\b", content):
            ent = calculate_shannon_entropy(token)
            if ent >= self.entropy_threshold:
                q = self.quarantine_mgr.quarantine_file(file_path, "HIGH_ENTROPY_TOKEN", ent)
                result.update({"is_clean": False, "rule_matched": "HIGH_ENTROPY_TOKEN", "entropy": ent, "quarantined_to": q})
                return result

        return result
