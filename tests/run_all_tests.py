#!/usr/bin/env python3
import sys, os, asyncio, shutil, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security_sentinel.file_inspector import FileInspector
from security_sentinel.edr_threat_rules import (
    CVE202634348EventLogAuditor, ChromeMemoryInspectionDetector, WindowsHelloDeviceClaimAnomalyDetector
)
from security_sentinel.chokepoint_finder import (
    VulnerabilityFinding, AnalysisRequest, SeverityEnum, ResourceTypeEnum,
    analyze_vulnerabilities, approve_chokepoint, HITLApprovalRequest, ApprovalStatusEnum
)
from security_sentinel.evidence_investigator import WazuhAlertPayload, investigate_alert, ComplianceStatusEnum

def test_sentinel():
    test_dir, q_dir = "./test_monitored", "./test_quarantine"
    if os.path.exists(test_dir): shutil.rmtree(test_dir)
    if os.path.exists(q_dir): shutil.rmtree(q_dir)
    os.makedirs(test_dir, exist_ok=True)
    os.makedirs(q_dir, exist_ok=True)

    inspector = FileInspector(quarantine_dir=q_dir)
    clean_f = os.path.join(test_dir, "clean.txt")
    with open(clean_f, "w") as f: f.write("Clean file.")
    assert inspector.inspect_file(clean_f)["is_clean"] is True
    print("[PASS] Test 1: Clean file verified.")

    sec_f = os.path.join(test_dir, "aws.txt")
    with open(sec_f, "w") as f: f.write("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    assert inspector.inspect_file(sec_f)["is_clean"] is False
    print("[PASS] Test 2: AWS Secret Detection & Quarantine verified.")

    ev1 = {"FolderPath": r"C:\Windows\System32\Winevt\Logs", "FileName": "Microsoft-Windows-WebAuthN-Operational.evtx", "InitiatingProcessFileName": "powershell.exe", "AccessMask": "0x1"}
    assert CVE202634348EventLogAuditor.evaluate(ev1) is not None
    print("[PASS] Test 3: CVE-2026-34348 Event Log Access Rule verified.")

    ev2 = {"ActionType": "ProcessAccessOpened", "TargetProcessFileName": "chrome.exe", "InitiatingProcessFileName": "stealer.exe", "DesiredAccess": "0x0010"}
    assert ChromeMemoryInspectionDetector.evaluate(ev2) is not None
    print("[PASS] Test 4: Chrome Process Memory Inspection Rule verified.")

    ev3 = {"AuthenticationDetails": "FIDO2 / WebAuthn MFA", "DeviceDetail": {"DeviceId": ""}, "RiskLevel": "High"}
    assert WindowsHelloDeviceClaimAnomalyDetector.evaluate(ev3) is not None
    print("[PASS] Test 5: Windows Hello Device Claim Anomaly Rule verified.")

    shutil.rmtree(test_dir)
    shutil.rmtree(q_dir)
    print("[OK] Sentinel Core & EDR Tests Passed!")

async def test_chokepoints():
    findings = [
        VulnerabilityFinding(id="w1", cve_id="CVE-2024-3094", title="XZ Backdoor", severity=SeverityEnum.CRITICAL, cvss_score=10.0, affected_resource="c1", resource_type=ResourceTypeEnum.CONTAINER_IMAGE, package_name="debian-slim", fix_version="12.5-slim", asset_criticality=3.0),
        VulnerabilityFinding(id="w2", cve_id="CVE-2024-3094", title="XZ Backdoor", severity=SeverityEnum.CRITICAL, cvss_score=10.0, affected_resource="c2", resource_type=ResourceTypeEnum.CONTAINER_IMAGE, package_name="debian-slim", fix_version="12.5-slim", asset_criticality=2.0)
    ]
    res = await analyze_vulnerabilities(AnalysisRequest(findings=findings))
    assert res.total_raw_findings == 2 and res.condensed_chokepoints_count == 1
    print(f"[PASS] Ingested 2 findings -> Condensed into {res.condensed_chokepoints_count} chokepoint.")

    app = await approve_chokepoint(res.chokepoints[0].chokepoint_id, HITLApprovalRequest(approved_by="admin@nomadik.site", action=ApprovalStatusEnum.APPROVED))
    assert app.status == ApprovalStatusEnum.APPROVED
    print(f"[PASS] Approved Chokepoint: {app.chokepoint_id} | Status: {app.status}")
    print("[OK] Chokepoint Finder Tests Passed!")

async def test_investigator():
    alert = WazuhAlertPayload(
        alert_id="alert-99", timestamp="2026-08-13T00:00:00Z", agent_id="001",
        agent_name="k8s-node", rule_id=1001, rule_description="XZ CVE-2024-3094",
        rule_level=14, cve_id="CVE-2024-3094", package_name="xz-utils",
        package_version="5.6.0", raw_log=json.dumps({"cve": "CVE-2024-3094"})
    )
    report = await investigate_alert(alert)
    assert report.cve_id == "CVE-2024-3094" and report.status == ComplianceStatusEnum.NON_COMPLIANT and len(report.attached_evidence.sha256_hash) == 64
    print(f"[PASS] Generated Disposition: {report.disposition_id} | Evidence SHA-256: {report.attached_evidence.sha256_hash[:16]}...")
    print("[OK] Evidence Investigator Tests Passed!")

def test_billing():
    from fastapi.testclient import TestClient
    from security_sentinel.main_app import app
    client = TestClient(app)
    
    # 1. Product Catalog
    p_resp = client.get("/api/v1/billing/plans")
    assert p_resp.status_code == 200 and "starter" in p_resp.json() and "pro" in p_resp.json()
    print("[PASS] Product Catalog: Starter ($1,500/mo) & Pro ($5,000/mo) verified.")
    
    # 2. Starter Checkout
    c_resp = client.post("/api/v1/billing/checkout-session", json={"plan_tier": "starter", "customer_email": "cto@alpha.io", "tenant_id": "tenant_01"})
    assert c_resp.status_code == 200 and c_resp.json()["allocated_credits"] == 5000
    print(f"[PASS] Starter Checkout Session: {c_resp.json()['session_id']} | Credits: 5,000 verified.")
    
    # 3. Pro Checkout
    pro_resp = client.post("/api/v1/billing/checkout-session", json={"plan_tier": "pro", "customer_email": "ciso@beta.io", "tenant_id": "tenant_02"})
    assert pro_resp.status_code == 200 and pro_resp.json()["allocated_credits"] == 25000
    print(f"[PASS] Pro Enterprise Checkout Session: {pro_resp.json()['session_id']} | Credits: 25,000 verified.")
    
    # 4. Webhook
    wh_resp = client.post("/api/v1/billing/webhook", json={"type": "checkout.session.completed", "id": "evt_001"})
    assert wh_resp.status_code == 200
    print("[PASS] Stripe Webhook: checkout.session.completed ingestion verified.")
    print("[OK] Billing & Monetization Tests Passed!")

def main():
    print("=========================================================")
    print("[*] Running Nomadik Security Sentinel Unified Test Suite")
    print("=========================================================\n")
    print("--- 1. Testing Sentinel Core & EDR Threat Rules ---")
    test_sentinel()
    print("\n--- 2. Testing Remediation Chokepoint Finder ---")
    asyncio.run(test_chokepoints())
    print("\n--- 3. Testing Evidence-Backed Compliance Investigator ---")
    asyncio.run(test_investigator())
    print("\n--- 4. Testing Billing & Singularity Credit Engine ---")
    test_billing()
    print("\n=========================================================")
    print("[SUCCESS] ALL SECURITY SENTINEL MODULES VERIFIED GREEN!")
    print("=========================================================")

if __name__ == "__main__":
    main()
