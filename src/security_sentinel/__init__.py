from security_sentinel.watcher import SentinelWatcher, SentinelEventHandler
from security_sentinel.file_inspector import FileInspector, QuarantineManager, calculate_shannon_entropy
from security_sentinel.edr_threat_rules import (
    EDRThreatEngine, ThreatAlert, CVE202634348EventLogAuditor,
    ChromeMemoryInspectionDetector, WindowsHelloDeviceClaimAnomalyDetector
)
from security_sentinel.chokepoint_finder import (
    Chokepoint, VulnerabilityFinding, AnalysisRequest, AnalysisResponse,
    HITLApprovalRequest, group_findings_into_chokepoints
)
from security_sentinel.evidence_investigator import (
    WazuhAlertPayload, AuditorDispositionReport, ComplianceControlMapping,
    EvidenceItem, investigate_alert
)
__version__ = "1.0.0"
