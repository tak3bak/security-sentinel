import pytest
from security_sentinel.quarantine import QuarantineManager

def test_quarantine_manager_init():
    qm = QuarantineManager()
    assert qm is not None
