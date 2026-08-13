import json, logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

logger = logging.getLogger("EDRThreatRules")

class ThreatAlert(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    advisory_id: str = "SEC-ADV-2026-0810"
    cve: Optional[str] = None
    description: str
    event_data: Dict[str, Any]
    recommendation: str

class CVE202634348EventLogAuditor:
    RULE_ID = "SEC-RULE-2026-001"
    NAME = "Windows Event Log Access Auditing (CVE-2026-34348 Exploitation)"
    SEVERITY = "Critical"
    CVE = "CVE-2026-34348"
    EXCLUDED_PROCESSES = {"svchost.exe", "lsass.exe", "services.exe", "system"}

    @classmethod
    def evaluate(cls, event: Dict[str, Any]) -> Optional[ThreatAlert]:
        fp = str(event.get("FolderPath", "") or event.get("folder_path", "")).lower()
        fn = str(event.get("FileName", "") or event.get("file_name", "")).lower()
        proc = str(event.get("InitiatingProcessFileName", "") or event.get("process_name", "")).lower()
        mask = str(event.get("AccessMask", "") or event.get("access_mask", "")).lower()

        if not (("system32\\winevt\\logs" in fp or "system32/winevt/logs" in fp) or ("webauthn" in fn or "system.evtx" in fn or "webauthn" in fp)):
            return None
        if proc in cls.EXCLUDED_PROCESSES: return None
        if mask and not any(flag in mask for flag in ["0x1", "0x80", "read"]): return None

        return ThreatAlert(
            rule_id=cls.RULE_ID, rule_name=cls.NAME, severity=cls.SEVERITY, cve=cls.CVE,
            description="Unauthorized process accessed WebAuthN/System event logs (CVE-2026-34348).",
            event_data=event, recommendation="Patch CVE-2026-34348 and isolate initiating process."
        )

class ChromeMemoryInspectionDetector:
    RULE_ID = "SEC-RULE-2026-002"
    NAME = "Chrome Process Memory Inspection (Golden Pass-ta-key)"
    SEVERITY = "High"
    EXCLUDED_PROCESSES = {"chrome.exe", "edr_agent.exe", "mssense.exe"}
    TARGET_FLAGS = {"0x10", "0x8", "0x0010", "0x0008", "0x1f0fff", "process_vm_read", "process_vm_operation"}

    @classmethod
    def evaluate(cls, event: Dict[str, Any]) -> Optional[ThreatAlert]:
        target = str(event.get("TargetProcessFileName", "") or event.get("target_process", "")).lower()
        proc = str(event.get("InitiatingProcessFileName", "") or event.get("initiating_process", "")).lower()
        access = str(event.get("DesiredAccess", "") or event.get("desired_access", "")).lower()

        if target != "chrome.exe" or proc in cls.EXCLUDED_PROCESSES: return None
        if not any(flag in access for flag in cls.TARGET_FLAGS): return None

        return ThreatAlert(
            rule_id=cls.RULE_ID, rule_name=cls.NAME, severity=cls.SEVERITY,
            description="Unauthorized process opened handle to chrome.exe with memory read/virtual flags.",
            event_data=event, recommendation="Deploy Credential Guard and inspect initiating binary."
        )

class WindowsHelloDeviceClaimAnomalyDetector:
    RULE_ID = "SEC-RULE-2026-003"
    NAME = "Windows Hello Sign-ins Lacking Device Claims Anomaly"
    SEVERITY = "High"

    @classmethod
    def evaluate(cls, event: Dict[str, Any]) -> Optional[ThreatAlert]:
        auth = str(event.get("AuthenticationDetails", "") or event.get("auth_details", "")).lower()
        dev_id = event.get("DeviceDetail", {}).get("DeviceId") if isinstance(event.get("DeviceDetail"), dict) else event.get("device_id")
        risk = str(event.get("RiskLevel", "") or event.get("risk_level", "")).lower()

        if not ("fido2" in auth or "windows hello" in auth): return None
        if bool(dev_id and str(dev_id).strip()) or risk == "low": return None

        return ThreatAlert(
            rule_id=cls.RULE_ID, rule_name=cls.NAME, severity=cls.SEVERITY,
            description="FIDO2 / Windows Hello authentication passed MFA without device identifier claims.",
            event_data=event, recommendation="Enforce Conditional Access device compliance policies."
        )

class EDRThreatEngine:
    def __init__(self, manifest_path: Optional[str] = None):
        self.rules_manifest = None
        if manifest_path:
            try:
                with open(manifest_path, "r", encoding="utf-8") as f: self.rules_manifest = json.load(f)
                logger.info(f"Loaded rules manifest from {manifest_path}")
            except Exception as e: logger.error(f"Manifest load error: {e}")

    def process_event(self, event: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        for det in [CVE202634348EventLogAuditor, ChromeMemoryInspectionDetector, WindowsHelloDeviceClaimAnomalyDetector]:
            a = det.evaluate(event)
            if a: alerts.append(a)
        return alerts
