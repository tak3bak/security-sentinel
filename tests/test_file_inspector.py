import pytest
import os
import tempfile
from security_sentinel.file_inspector import FileInspector, calculate_shannon_entropy

def test_shannon_entropy_calculation():
    assert calculate_shannon_entropy("AAAAAAAAAA") == 0.0
    assert calculate_shannon_entropy("8fA#k9$zL@2!qW5&") > 3.5

def test_file_inspector_scan():
    inspector = FileInspector()
    assert inspector is not None
