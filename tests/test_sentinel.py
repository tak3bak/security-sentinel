import os, sys, shutil, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security_sentinel.file_inspector import FileInspector
from security_sentinel.edr_threat_rules import (
    CVE202634348EventLogAuditor,
    ChromeMemoryInspectionDetector,
    WindowsHelloDeviceClaimAnomalyDetector
)

def test_sentinel_pipeline():
    test_dir = "./test_monitored"
    quarantine_dir = "./test_quarantine"
    if os.path.exists(test_dir): shutil.rmtree(test_dir)
    if os.path.exists(quarantine_dir): shutil.rmtree(quarantine_dir)
    os.makedirs(test_dir, exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)

    inspector = FileInspector(quarantine_dir=quarantine_dir)

    # Test clean file
    clean_file = os.path.join(test_dir, "clean.txt")
    with open(clean_file, "w") as f: f.write("Clean text.")
    res1 = inspector.inspect_file(clean_file)
    assert res1["is_clean"] is True
    print("[PASS] Test 1: Clean file verified.")

    # Test AWS secret
    secret_file = os.path.join(test_dir, "aws.txt")
    with open(secret_file, "w") as f: f.write("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    res2 = inspector.inspect_file(secret_file)
    assert res2["is_clean"] is False
    print("[PASS] Test 2: AWS Secret Detection verified.")

    # Test EDR Rules
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
    shutil.rmtree(quarantine_dir)
    print("\n[OK] Sentinel Core & EDR Tests Passed!")

if __name__ == "__main__":
    test_sentinel_pipeline()
