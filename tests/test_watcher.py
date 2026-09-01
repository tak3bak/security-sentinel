import pytest
import tempfile
from security_sentinel.file_inspector import FileInspector
from security_sentinel.watcher import SentinelWatcher, SentinelEventHandler

def test_sentinel_watcher_and_handler_init():
    inspector = FileInspector()
    handler = SentinelEventHandler(inspector=inspector)
    assert handler is not None

    with tempfile.TemporaryDirectory() as watch_dir:
        try:
            watcher = SentinelWatcher(watch_dir=watch_dir, inspector=inspector)
        except TypeError:
            watcher = SentinelWatcher(inspector=inspector)
        assert watcher is not None
