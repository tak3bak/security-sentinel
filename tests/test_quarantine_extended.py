import os
from unittest.mock import patch
from security_sentinel.quarantine import QuarantineManager

def test_quarantine_manager_init():
    manager = QuarantineManager()
    assert manager is not None
    assert os.path.exists(manager.quarantine_dir)

def test_quarantine_manager_fallback():
    with patch("os.makedirs", side_effect=[OSError("Permission denied"), None]):
        manager = QuarantineManager(quarantine_dir="/restricted/path")
        assert "quarantine_fallback" in manager.quarantine_dir
