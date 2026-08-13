import os, sys, asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security_sentinel.chokepoint_finder import (
    VulnerabilityFinding, AnalysisRequest, SeverityEnum, ResourceTypeEnum,
    analyze_vulnerabilities, approve_chokepoint, HITLApprovalRequest, ApprovalStatusEnum
)

async def test_flow():
    findings = [
        VulnerabilityFinding(id="w1", cve_id="CVE-2024-3094", title="XZ Backdoor", severity=SeverityEnum.CRITICAL, cvss_score=10.0, affected_resource="c1", resource_type=ResourceTypeEnum.CONTAINER_IMAGE, package_name="debian-slim", fix_version="12.5-slim", asset_criticality=3.0),
        VulnerabilityFinding(id="w2", cve_id="CVE-2024-3094", title="XZ Backdoor", severity=SeverityEnum.CRITICAL, cvss_score=10.0, affected_resource="c2", resource_type=ResourceTypeEnum.CONTAINER_IMAGE, package_name="debian-slim", fix_version="12.5-slim", asset_criticality=2.0)
    ]
    res = await analyze_vulnerabilities(AnalysisRequest(findings=findings))
    assert res.total_raw_findings == 2
    assert res.condensed_chokepoints_count == 1
    print(f"[PASS] Ingested 2 findings -> Condensed into {res.condensed_chokepoints_count} chokepoint.")

    app = await approve_chokepoint(res.chokepoints[0].chokepoint_id, HITLApprovalRequest(approved_by="admin@nomadik.site", action=ApprovalStatusEnum.APPROVED))
    assert app.status == ApprovalStatusEnum.APPROVED
    print(f"[PASS] Approved Chokepoint: {app.chokepoint_id} | Status: {app.status}")
    print("\n[OK] Chokepoint Finder Tests Passed!")

if __name__ == "__main__":
    asyncio.run(test_flow())
