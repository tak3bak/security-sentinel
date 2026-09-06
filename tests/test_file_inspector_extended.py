import os
import json
import pytest
from security_sentinel.file_inspector import FileInspector, QuarantineManager, calculate_shannon_entropy

def test_calculate_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0

def test_quarantine_manager_nonexistent_file(tmp_path):
    qm = QuarantineManager(str(tmp_path / "q"))
    assert qm.quarantine_file(str(tmp_path / "nonexistent.txt"), "RULE", 1.0) is None

def test_quarantine_manager_exception(tmp_path, monkeypatch):
    qm = QuarantineManager(str(tmp_path / "q"))
    test_file = tmp_path / "test.txt"
    test_file.write_text("secret")
    
    monkeypatch.setattr("shutil.move", lambda src, dst: (_ for _ in ()).throw(Exception("Move failed")))
    
    res = qm.quarantine_file(str(test_file), "RULE", 1.0)
    assert res is None

def test_file_inspector_nonexistent_or_quarantined_file(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"))
    res = fi.inspect_file(str(tmp_path / "missing.txt"))
    assert res["is_clean"] is True

    q_file = tmp_path / "q" / "sample.txt"
    q_file.write_text("content")
    res2 = fi.inspect_file(str(q_file))
    assert res2["is_clean"] is True

def test_file_inspector_read_exception(tmp_path, monkeypatch):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"))
    f = tmp_path / "locked.txt"
    f.write_text("content")
    
    with monkeypatch.context() as m:
        m.setattr("builtins.open", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Locked")))
        res = fi.inspect_file(str(f))
        assert res["is_clean"] is True

def test_file_inspector_json_non_list_event(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"))
    f = tmp_path / "event.json"
    f.write_text(json.dumps({"event_id": "123", "action": "test"}))
    res = fi.inspect_file(str(f))
    assert res["is_clean"] is True

def test_file_inspector_json_invalid(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"))
    f = tmp_path / "bad.json"
    f.write_text("{invalid json")
    res = fi.inspect_file(str(f))
    assert res["is_clean"] is True

def test_file_inspector_detects_secret_pattern(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"), entropy_threshold=5.0)
    f = tmp_path / "aws_key.txt"
    f.write_text("Access Key: AKIAIOSFODNN7EXAMPLE")
    res = fi.inspect_file(str(f))
    assert res["is_clean"] is False
    assert res["rule_matched"] == "AWS_ACCESS_KEY_ID"
    assert res["quarantined_to"] is not None

def test_file_inspector_detects_high_entropy_token(tmp_path):
    fi = FileInspector(quarantine_dir=str(tmp_path / "q"), entropy_threshold=3.0)
    f = tmp_path / "token.txt"
    f.write_text("Token: 4k9F8s7D6c5B4a3Z2y1X0w9V8u7T6s5R4q3P2o1N")
    res = fi.inspect_file(str(f))
    assert res["is_clean"] is False
    assert res["rule_matched"] == "HIGH_ENTROPY_TOKEN"
    assert res["quarantined_to"] is not None
