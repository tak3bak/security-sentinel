from typing import Optional
from security_sentinel.file_inspector import FileInspector

class SentinelEventHandler:
    def __init__(self, inspector: Optional[FileInspector] = None):
        self.inspector = inspector or FileInspector()

class SentinelWatcher:
    def __init__(self, watch_dir: str = ".", inspector: Optional[FileInspector] = None):
        self.watch_dir = watch_dir
        self.inspector = inspector or FileInspector()
        self.handler = SentinelEventHandler(inspector=self.inspector)
