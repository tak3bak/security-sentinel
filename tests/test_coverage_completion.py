import os
import json
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from security_sentinel.edr_threat_rules import EDRThreatEngine, ThreatAlert
from security_sentinel.evidence_investigator import router as investigator_router, DISPOSITION_STORE
from security_sentinel.file_inspector import FileInspector

app = FastAPI()
app.include_router(investigator_router)
client = TestClient(app)

def test_edr_manifest_load_error(tmp_path):
    bad_manifest = tmp_path / "bad_manifest.json"
    bad_manifest.write_text("{invalid json")
    engine = EDRThreatEngine(manifest_path=str(bad_manifest))
    assert engine.rules_manifest is None

def test_evidence_investigator_list_dispositions():
    DISPOSITION_STORE.clear()
    res = client.get("/api/v1/investigation/dispositions")
    assert res.status_code == 200
    assert res.json() == []

def test_file_inspector_edr_alert_branch(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"))
    f = tmp_path / "alert_event.json"
    event_data = {
        "event_id": 4688,
        "process_name": "suspicious.exe",
        "command_line": "powershell -EncodedCommand AABBBCC="
    }
    f.write_text(json.dumps(event_data))
    
    mock_alert = ThreatAlert(
        rule_id="CVE_2026_MOCK",
        rule_name="Mock Alert",
        severity="High",
        description="Mock description",
        event_data=event_data,
        recommendation="Mitigate"
    )
    with patch.object(fi.edr_engine, "process_event", return_value=[mock_alert]):
        res2 = fi.inspect_file(str(f))
        assert res2["is_clean"] is False
        assert res2["rule_matched"] == "CVE_2026_MOCK"
        assert res2["quarantined_to"] is not None
