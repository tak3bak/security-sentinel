import os, sys, asyncio, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security_sentinel.evidence_investigator import WazuhAlertPayload, investigate_alert, ComplianceStatusEnum

async def test_investigation():
    alert = WazuhAlertPayload(
        alert_id="alert-99", timestamp="2026-08-13T00:00:00Z", agent_id="001",
        agent_name="k8s-node", rule_id=1001, rule_description="XZ CVE-2024-3094",
        rule_level=14, cve_id="CVE-2024-3094", package_name="xz-utils",
        package_version="5.6.0", raw_log=json.dumps({"cve": "CVE-2024-3094"})
    )
    report = await investigate_alert(alert)
    assert report.cve_id == "CVE-2024-3094"
    assert report.status == ComplianceStatusEnum.NON_COMPLIANT
    assert len(report.attached_evidence.sha256_hash) == 64
    print(f"[PASS] Generated Disposition: {report.disposition_id} | Evidence SHA-256: {report.attached_evidence.sha256_hash[:16]}...")
    print("\n[OK] Evidence Investigator Tests Passed!")

if __name__ == "__main__":
    asyncio.run(test_investigation())
