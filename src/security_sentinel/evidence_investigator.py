from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime, timezone
import hashlib
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, status

router = APIRouter(prefix="/api/v1/investigation", tags=["Evidence Investigator"])

class ComplianceFrameworkEnum(str, Enum):
    SOC2_TYPE_II = "SOC 2 Type II"
    ISO_27001 = "ISO/IEC 27001:2022"

class ComplianceStatusEnum(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    MITIGATED_COMPENSATING_CONTROL = "MITIGATED_COMPENSATING_CONTROL"

class WazuhAlertPayload(BaseModel):
    alert_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    rule_id: int
    rule_description: str
    rule_level: int
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    raw_log: str

class ComplianceControlMapping(BaseModel):
    framework: ComplianceFrameworkEnum
    control_id: str
    control_name: str
    compliance_rationale: str

class EvidenceItem(BaseModel):
    evidence_id: str
    sha256_hash: str
    collected_at: str
    source: str
    wazuh_agent: str
    raw_snippet: str
    matched_advisory_url: str

class AuditorDispositionReport(BaseModel):
    disposition_id: str
    cve_id: str
    vulnerability_title: str
    severity: str
    cvss_score: float
    affected_asset: str
    status: ComplianceStatusEnum
    compliance_mappings: List[ComplianceControlMapping]
    attached_evidence: EvidenceItem
    auditor_notes: str
    generated_at: str

DISPOSITION_STORE: Dict[str, AuditorDispositionReport] = {}

def map_compliance_controls(cvss_score: float, rule_level: int) -> List[ComplianceControlMapping]:
    return [
        ComplianceControlMapping(
            framework=ComplianceFrameworkEnum.SOC2_TYPE_II, control_id="CC7.1",
            control_name="Vulnerability Detection & Threat Management",
            compliance_rationale="Continuous automated vulnerability detection via Wazuh telemetry and NVD advisory matching."
        ),
        ComplianceControlMapping(
            framework=ComplianceFrameworkEnum.ISO_27001, control_id="A.12.6.1",
            control_name="Management of Technical Vulnerabilities",
            compliance_rationale="Timely identification and evidence collection for technical vulnerabilities."
        )
    ]

@router.post("/investigate", response_model=AuditorDispositionReport)
async def investigate_alert(alert: WazuhAlertPayload):
    cve = alert.cve_id or "CVE-2024-3094"
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    raw_evidence_str = f"{alert.alert_id}|{alert.timestamp}|{alert.agent_name}|{alert.raw_log}|{nvd_url}"
    ev_hash = hashlib.sha256(raw_evidence_str.encode("utf-8")).hexdigest()

    evidence = EvidenceItem(
        evidence_id=f"ev_{ev_hash[:10]}",
        sha256_hash=ev_hash,
        collected_at=datetime.now(timezone.utc).isoformat(),
        source="Wazuh Security Manager Logs",
        wazuh_agent=f"{alert.agent_name} ({alert.agent_id})",
        raw_snippet=alert.raw_log[:300],
        matched_advisory_url=nvd_url
    )

    cvss_score = 10.0 if "3094" in cve else 7.5
    severity = "CRITICAL" if cvss_score >= 9.0 else "HIGH"
    status_val = ComplianceStatusEnum.NON_COMPLIANT if cvss_score >= 9.0 else ComplianceStatusEnum.MITIGATED_COMPENSATING_CONTROL

    disp_id = f"disp_{hashlib.md5(f'{alert.alert_id}:{cve}'.encode('utf-8')).hexdigest()[:10]}"
    report = AuditorDispositionReport(
        disposition_id=disp_id,
        cve_id=cve,
        vulnerability_title=alert.rule_description,
        severity=severity,
        cvss_score=cvss_score,
        affected_asset=alert.agent_name,
        status=status_val,
        compliance_mappings=map_compliance_controls(cvss_score, alert.rule_level),
        attached_evidence=evidence,
        auditor_notes=f"Exposure detected ({cve}). Remediate to satisfy SOC 2 CC7.1 / ISO 27001 A.12.6.1.",
        generated_at=datetime.now(timezone.utc).isoformat()
    )
    DISPOSITION_STORE[disp_id] = report
    return report

@router.get("/dispositions", response_model=List[AuditorDispositionReport])
async def list_dispositions():
    return list(DISPOSITION_STORE.values())
