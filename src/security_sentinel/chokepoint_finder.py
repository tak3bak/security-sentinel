from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime, timezone
import hashlib, math
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, status

router = APIRouter(prefix="/api/v1/chokepoints", tags=["Chokepoint Finder"])

class SeverityEnum(str, Enum):
    CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"

class ResourceTypeEnum(str, Enum):
    CONTAINER_IMAGE, PACKAGE, IAM_ROLE, HOST_CONFIG = "container_image", "package", "iam_role", "host_config"

class RemediationTypeEnum(str, Enum):
    BASE_IMAGE_UPDATE = "BASE_IMAGE_UPDATE"
    PACKAGE_UPGRADE = "PACKAGE_UPGRADE"
    IAM_POLICY_REVISION = "IAM_POLICY_REVISION"
    CONFIG_HARDENING = "CONFIG_HARDENING"

class ApprovalStatusEnum(str, Enum):
    PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED = "PENDING_APPROVAL", "APPROVED", "REJECTED", "EXECUTED"

class VulnerabilityFinding(BaseModel):
    id: str
    cve_id: Optional[str] = None
    title: str
    severity: SeverityEnum = SeverityEnum.HIGH
    cvss_score: float = 0.0
    affected_resource: str
    resource_type: ResourceTypeEnum = ResourceTypeEnum.PACKAGE
    package_name: Optional[str] = None
    current_version: Optional[str] = None
    fix_version: Optional[str] = None
    iam_role_name: Optional[str] = None
    suggested_policy: Optional[str] = None
    asset_criticality: float = 1.0
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

class Chokepoint(BaseModel):
    chokepoint_id: str
    remediation_type: RemediationTypeEnum
    target_identifier: str
    description: str
    finding_ids: List[str]
    affected_assets: List[str]
    affected_assets_count: int
    total_findings_count: int
    max_cvss_score: float
    weighted_risk_score: float
    remediation_action_plan: str
    status: ApprovalStatusEnum = ApprovalStatusEnum.PENDING_APPROVAL
    approved_by: Optional[str] = None
    approval_timestamp: Optional[str] = None
    remediation_notes: Optional[str] = None

class AnalysisRequest(BaseModel):
    findings: List[VulnerabilityFinding]

class AnalysisResponse(BaseModel):
    total_raw_findings: int
    condensed_chokepoints_count: int
    chokepoints: List[Chokepoint]

class HITLApprovalRequest(BaseModel):
    approved_by: str
    action: ApprovalStatusEnum
    remediation_notes: Optional[str] = None

CHOKEPOINT_STORE: Dict[str, Chokepoint] = {}

def generate_chokepoint_id(remediation_type: str, target: str) -> str:
    return f"chk_{hashlib.sha256(f'{remediation_type}:{target}'.encode()).hexdigest()[:12]}"

def calculate_weighted_risk(max_cvss: float, count: int, max_crit: float) -> float:
    return round(max_cvss * (1.0 + (0.15 * math.log2(count + 1))) * max_crit, 2)

def group_findings_into_chokepoints(findings: List[VulnerabilityFinding]) -> List[Chokepoint]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.resource_type == ResourceTypeEnum.CONTAINER_IMAGE and f.fix_version:
            rem_type = RemediationTypeEnum.BASE_IMAGE_UPDATE
            target = f"{f.package_name or 'base_image'}:{f.fix_version}"
            desc = f"Update base image '{f.package_name}' to version {f.fix_version}."
            plan = f"Rebuild and deploy docker container with base image {target}."
        elif f.resource_type == ResourceTypeEnum.IAM_ROLE and f.iam_role_name:
            rem_type = RemediationTypeEnum.IAM_POLICY_REVISION
            target = f"role/{f.iam_role_name}"
            desc = f"Restrict permissions on IAM Role '{f.iam_role_name}' to least privilege."
            plan = f"Apply policy update '{f.suggested_policy or 'LeastPrivilegePolicy'}' to IAM Role {f.iam_role_name}."
        elif f.package_name and f.fix_version:
            rem_type = RemediationTypeEnum.PACKAGE_UPGRADE
            target = f"{f.package_name} -> {f.fix_version}"
            desc = f"Upgrade package '{f.package_name}' to version {f.fix_version}."
            plan = f"Run package manager update: apt-get/pip install {f.package_name}=={f.fix_version}."
        else:
            rem_type = RemediationTypeEnum.CONFIG_HARDENING
            target = f"{f.affected_resource}:{f.title}"
            desc = f"Harden system configuration for '{f.title}' on resource {f.affected_resource}."
            plan = f"Apply security baseline configuration fix for {f.title}."

        key = f"{rem_type.value}:{target}"
        if key not in grouped:
            grouped[key] = {"rem_type": rem_type, "target": target, "description": desc, "plan": plan, "findings": [], "assets": set(), "cvss": [], "crit": []}
        grouped[key]["findings"].append(f.id)
        grouped[key]["assets"].add(f.affected_resource)
        grouped[key]["cvss"].append(f.cvss_score)
        grouped[key]["crit"].append(f.asset_criticality)

    chks: List[Chokepoint] = []
    for key, data in grouped.items():
        chk_id = generate_chokepoint_id(data["rem_type"].value, data["target"])
        max_cvss = max(data["cvss"]) if data["cvss"] else 0.0
        max_crit = max(data["crit"]) if data["crit"] else 1.0
        cnt = len(data["findings"])
        score = calculate_weighted_risk(max_cvss, cnt, max_crit)
        chk = Chokepoint(
            chokepoint_id=chk_id, remediation_type=data["rem_type"], target_identifier=data["target"],
            description=data["description"], finding_ids=data["findings"],
            affected_assets=list(data["assets"]), affected_assets_count=len(data["assets"]),
            total_findings_count=cnt, max_cvss_score=max_cvss, weighted_risk_score=score,
            remediation_action_plan=data["plan"]
        )
        CHOKEPOINT_STORE[chk_id] = chk
        chks.append(chk)
    chks.sort(key=lambda x: x.weighted_risk_score, reverse=True)
    return chks

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_vulnerabilities(payload: AnalysisRequest):
    if not payload.findings:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Findings list cannot be empty.")
    chks = group_findings_into_chokepoints(payload.findings)
    return AnalysisResponse(total_raw_findings=len(payload.findings), condensed_chokepoints_count=len(chks), chokepoints=chks)

@router.get("/", response_model=List[Chokepoint])
async def list_chokepoints(status_filter: Optional[ApprovalStatusEnum] = Query(None, alias="status")):
    res = list(CHOKEPOINT_STORE.values())
    if status_filter:
        res = [c for c in res if c.status == status_filter]
    res.sort(key=lambda x: x.weighted_risk_score, reverse=True)
    return res

@router.post("/{chokepoint_id}/approve", response_model=Chokepoint)
async def approve_chokepoint(chokepoint_id: str, request: HITLApprovalRequest):
    if chokepoint_id not in CHOKEPOINT_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chokepoint not found.")
    chk = CHOKEPOINT_STORE[chokepoint_id]
    chk.status = request.action
    chk.approved_by = request.approved_by
    chk.approval_timestamp = datetime.now(timezone.utc).isoformat()
    chk.remediation_notes = request.remediation_notes
    CHOKEPOINT_STORE[chokepoint_id] = chk
    return chk
