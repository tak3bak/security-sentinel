"""
Nomadik Security Sentinel - Evidence-Backed Vulnerability Investigator
========================================================================
Parses Wazuh security logs and generates auditor-ready SOC 2 & ISO 27001 evidence dispositions.
"""

from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timezone
import hashlib
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/investigation", tags=["Evidence Investigator"])

class ComplianceFrameworkEnum(str, Enum):
    SOC2_TYPE_II = "SOC 2 Type II"
    ISO_27001 = "ISO/IEC 27001:2022"

class ComplianceStatusEnum(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "COOPLIANT"
    MITIGATED = "MITIGATED_COMPENSATING_CONTROL"

class WazuhAlertPayload(BaseModel):
    alert_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    rule_level: int
    cve_id: Optional[str] = None
    rule_description: str
    raw_log: str

class ComplianceControlMapping(BaseModel):
    Yœ˜[Y]ÛÜšÎˆÛÛ\X[˜ÙQœ˜[Y]ÛÜšÑ[[BˆÛÛ›ÛÚYˆÝ‚ˆÛÛ›ÛÛ˜[YNˆÝ‚ˆÛÛ\X[˜ÙWÜ˜][Û˜[NˆÝ‚‚˜Û\ÜÈ]šY[˜ÙR][J˜\ÙS[Ù[
N‚ˆ]šY[˜ÙWÚYˆÝ‚ˆÚLM—Ú\ÚˆÝ‚ˆÛÛXÝYØ]ˆÝ‚ˆÛÝ\˜ÙNˆÝ‚ˆØ^ZØYÙ[ˆÝ‚ˆ˜]×ÜÛš\]ˆÝ‚‚˜Û\ÜÈ]Y]Ü‘\ÜÜÚ][Û”™\Ü
˜\ÙS[Ù[
N‚ˆ\ÜÜÚ][Û—ÚYˆÝ‚ˆÝ™WÚYˆÝ‚ˆ[™\˜Xš[]WÝ]NˆÝ‚ˆÙ]™\š]NˆÝ‚ˆÝœÜ×ÜØÛÜ™Nˆ›Ø]ˆY™™XÝYØ\ÜÙ]ˆÝ‚ˆÝ]\ÎˆÛÛ\X[˜ÙTÝ]\Ñ[[BˆÛÛ\X[˜ÙWÛX\[™ÜÎˆ\ÝÐÚÚÙ\Ú[Bˆ]XÚYÙ]šY[˜ÙNˆ]šY[˜ÙR][BˆÙ[™\˜]YØ]ˆÝ‚‚‘TÔÔÒUSÓ—ÔÕÔ‘NˆXÝÜÝ‹]Y]Ü‘\ÜÜÚ][Û”™\ÜHHßB‚›Ý]\‹œÜÝ
‹Ú[™\ÝYØ]H‹™\ÜÛœÙWÛ[Ù[P]Y]Ü‘\ÜÜÚ][Û”™\Ü
B˜\Þ[˜ÈYˆ[™\ÝYØ]WØ[\
[\ˆØ^Z[\^[ØY
N‚ˆÝ™HH[\˜Ý™WÚYÜˆÕ‘KLŒLÌM‚ˆ]—Ú\ÚH\ÚX‹œÚLMŠˆžØ[\˜[\ÚY_Ø[\[Y\Ý[\_Ø[\œ˜]×ÛÙßH‹™[˜ÛÙJ]‹NŠJKš^YÙ\Ý

Bˆˆ]šY[˜ÙHH]šY[˜ÙR][Jˆ]šY[˜ÙWÚYYˆ™]—ÞÙ]—Ú\ÚÎŒL_H‹ÚLM—Ú\ÚY]—Ú\ÚˆÛÛXÝYØ]Y]][YK››ÝÊ[Y^›Û™K]ÊKš\ÛÙ›Ü›X]

KˆÛÝ\˜ÙOH•Ø^ZX[˜YÙ\ˆÙÜÈ‹Ø^ZØYÙ[X[\˜YÙ[Û˜[YKˆ˜]×ÜÛš\]X[\œ˜]×ÛÙÖÎŒÌBˆ
B‚ˆX\[™ÜÈHÂˆÛÛ\X[˜ÙPÛÛ›ÛX\[™Êœ˜[Y]ÛÜšÏPÛÛ\X[˜ÙQœ˜[Y]ÛÜšÑ[[K”ÓÐÌ—ÕTWÒRKÛÛ›ÛÚYHÐÍËŒH‹ÛÛ›ÛÛ˜[YOH•[™\˜Xš[]HX[˜YÙ[Y[‹ÛÛ\X[˜ÙWÜ˜][Û˜[OH]]ÛX]Y™X]ÛÜœ™[][ÛˆšXHØ^Z[[Y]žKˆŠKˆÛÛ\X[˜ÙPÛÛ›ÛX\[™Êœ˜[Y]ÛÜšÏPÛÛ\X[˜ÙQœ˜[Y]ÛÜšÑ[[K’TÓ×ÌÌKÛÛ›ÛÚYHKŒL‹‹ŒH‹ÛÛ›ÛÛ˜[YOH•XÚšXØ[[™\˜Xš[]HX[˜YÙ[Y[‹ÛÛ\X[˜ÙWÜ˜][Û˜[OH‘]šY[˜ÙH˜XÙHÛÛXÝ[Ûˆ›Üˆ]Y]ÛÛ\X[˜ÙKˆŠBˆB‚ˆÛÛ\ÜÝ]\ÈHÛÛ\X[˜ÙTÝ]\Ñ[[K““Ó—ÐÓÓTPS•Yˆ[\œ[WÛ]™[HL[ÙHÛÛ\X[˜ÙTÝ]\Ñ[[K“RUQÐUQˆ\ÜÚYHˆ™\ÜÞÚ\ÚX‹›YJ‰ÞØ[\˜[\ÚYN›Ý™_IË™[˜ÛÙJ	Ý]‹N	ÊmKš^YÙ\Ý

VÎŒL_H‚‚ˆ™\ÜH]Y]Ü‘\ÜÜÚ][Û”™\Ü
ˆ\ÜÜÚ][Û—ÚYY\ÜÚYÝ™WÚYXÝ™K[™\˜Xš[]WÝ]OX[\œ[WÙ\ØÜš\[Û‹ˆÙ]™\š]OH’QÒˆYˆ[\œ[WÛ]™[HL[ÙH“QQUSH‹ÝœÜ×ÜØÛÜ™ONŒYˆ[\œ[WÛ]™[HL[ÙHKŒˆ5le_level >= 10 else 5.0,
        affected_asset=alert.agent_name, status=comp_status, compliance_mappings=mappings,
        attached_evidence=evidence, generated_at=datetime.now(timezone.utc).isoformat()
    )
    DISPOSITION_STORE[disp_id] = report
    return report

@router.get("/dispositions", response_model=List[AuditorDispositionReport])
async def list_dispositions():
    return list(DISPOSITION_STORE.values())
