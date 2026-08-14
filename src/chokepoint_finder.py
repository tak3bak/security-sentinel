"""
Nomadik Security Sentinel - Chokepoint Finder Router
=====================================================
Groups raw vulnerability findings by the single required remediation action.
"""

from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime, timezone
import hashlib
import math
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, status

router = APIRouter(prefix="/api/v1/chokepoints", tags=["Chokepoint Finder"])


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ResourceTypeEnum(str, Enum):
    CONTAINER_IMAGE = "container_image"
    PACKAGE = "package"
    IAM_ROLE = "iam_role"
    HOST_CONFIG = "host_config"


class RemediationTypeEnum(str, Enum):
    BASE_IMAGE_UPDATE = "BASE_IMAGE_UPDATE"
    PACKAGE_UPGRADE = "PACKAGE_UPGRADE"
    IAM_POLICY_REVISION = "IAM_POLICY_REVISION"
    CONFIG_HARDENING = "CONFIG_HARDENING"


class ApprovalStatusEnum(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    cve_id: Optional[str] = None
    title: str
    severity: SeverityEnum = SeverityEnum.HIGH
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    affected_resource: str
    resource_type: ResourceTypeEnum = ResourceTypeEnum.PACKAGE
    package_name: Optional[str] = None
    current_version: Optional[str] = None
    fix_version: Optional[str] = None
    iam_role_name: Optional[str] = None
    suggested_policy: Optional[str] = None
    asset_criticality: float = Field(1.0, ge=1.0, le=3.0)
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


def generate_chokepoint_id(remediation_type: str, target_identifier: str) -> str:
    raw_key = f"{remediation_type}:{target_identifier}".encode("utf-8")
    return f"chk_{hashlib.sha256(raw_key).hexdigest()[:12]}"


def calculate_weighted_risk(
    max_cvss: float, finding_count: int, max_criticality: float
) -> float:
    count_multiplier = 1.0 + (0.15 * math.log2(finding_count + 1))
    return round(max_cvss * count_multiplier * max_criticality, 2)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_vulnerabilities(payload: AnalysisRequest):
    grouped_data: Dict[str, Dict[str, Any]] = {}
    for finding in payload.findings:
        if (
            finding.resource_type == ResourceTypeEnum.CONTAINER_IMAGE
            and finding.fix_version
        ):
            rem_type = RemediationTypeEnum.BASE_IMAGE_UPDATE
            target = f"{finding.package_name or 'base'}:{finding.fix_version}"
            desc = f"Upgrade base image '{finding.package_name}' to version {finding.fix_version}."
            plan = f"Rebuild container using base image {target}."
        elif finding.package_name and finding.fix_version:
            rem_type = RemediationTypeEnum.PACKAGE_UPGRADE
            target = f"{finding.package_name} -> {finding.fix_version}"
            desc = f"Upgrade package '{finding.package_name}' to {finding.fix_version}."
            plan = f"Run package upgrade for {finding.package_name}."
        else:
            rem_type = RemediationTypeEnum.CONFIG_HARDENING
            target = f"{finding.affected_resource}:{finding.title}"
            desc = f"Harden configuration for {finding.title}."
            plan = f"Apply baseline security hardening."

        key = f"{rem_type.value}:{target}"
        if key not in grouped_data:
            grouped_data[key] = {
                "rem_type": rem_type,
                "target": target,
                "description": desc,
                "plan": plan,
                "findings": [],
                "assets": set(),
                "cvss_scores": [],
                "criticalities": [],
            }
        grouped_data[key]["findings"].append(finding.id)
        grouped_data[key]["assets"].add(finding.affected_resource)
        grouped_data[key]["cvss_scores"].append(finding.cvss_score)
        grouped_data[key]["criticalities"].append(finding.asset_criticality)

    chokepoints: List[Chokepoint] = []
    for key, data in grouped_data.items():
        chk_id = generate_chokepoint_id(data["rem_type"].value, data["target"])
        max_cvss = max(data["cvss_scores"]) if data["cvss_scores"] else 0.0
        max_crit = max(data["criticalities"]) if data["criticalities"] else 1.0
        weighted_score = calculate_weighted_risk(
            max_cvss, len(data["findings"]), max_crit
        )

        chk = Chokepoint(
            chokepoint_id=chk_id,
            remediation_type=data["rem_type"],
            target_identifier=data["target"],
            description=data["description"],
            finding_ids=data["findings"],
            affected_assets=list(data["assets"]),
            affected_assets_count=len(data["assets"]),
            total_findings_count=len(data["findings"]),
            max_cvss_score=max_cvss,
            weighted_risk_score=weighted_score,
            remediation_action_plan=data["plan"],
        )
        CHOKEPOINT_STORE[chk_id] = chk
        chokepoints.append(chk)

    chokepoints.sort(key=lambda x: x.weighted_risk_score, reverse=True)
    return AnalysisResponse(
        total_raw_findings=len(payload.findings),
        condensed_chokepoints_count=len(chokepoints),
        chokepoints=chokepoints
    )


@router.get("/", response_model=List[Chokepoint])
async def list_chokepoints():
    return list(CHOKEPOINT_STORE.values())


@router.post("/{chokepoint_id}/approve", response_model=Chokepoint)
async def approve_chokepoint(chokepoint_id: str, request: HITLApprovalRequest):
    if chokepoint_id not in CHOKEPOINT_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Chokepoint not found."
        )
    chk = CHOKEPOINT_STORE[chokepoint_id]
    chk.status = request.action
    chk.approved_by = request.approved_by
    chk.approval_timestamp = datetime.now(timezone.utc).isoformat()
    chk.remediation_notes = request.remediation_notes
    CHOKEPOINT_STORE[chokepoint_id] = chk
    return chk
