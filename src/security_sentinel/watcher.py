import os
import time
import threading
import logging
from security_sentinel.file_inspector import FileInspector

logger = logging.getLogger("SentinelWatcher")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    class FileSystemEventHandler:
        pass

class SentinelEventHandler(FileSystemEventHandler):
    def __init__(self, inspector: FileInspector):
        super().__init__()
        self.inspector = inspector

    def _process_event(self, event):
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", str(event))
        event_type = getattr(event, "event_type", "detected")
        logger.info(f"Filesystem event: {event_type} on {src_path}")
        self.inspector.inspect_file(src_path)

    def on_created(self, event):
        self._process_event(event)

    def on_modified(self, event):
        self._process_event(event)

class PollingObserver:
    """Zero-dependency polling fallback for Termux and lightweight container environments."""
    def __init__(self):
        self._running = False
        self._thread = None
        self._paths = []
        self._known_mtimes = {}

    def schedule(self, event_handler, path: str, recursive: bool = True):
        self._paths.append((event_handler, os.path.abspath(path), recursive))

    def _poll_loop(self):
        while self._running:
            for handler, root_path, recursive in self._paths:
                if not os.path.exists(root_path):
                    continue
                for root, _, files in os.walk(root_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            mtime = os.path.getmtime(full_path)
                            if full_path not in self._known_mtimes:
                                self._known_mtimes[full_path] = mtime
                                handler.on_created(full_path)
                            elif self._known_mtimes[full_path] != mtime:
                                self._known_mtimes[full_path] = mtime
                                handler.on_modified(full_path)
                        except OSError:
                            pass
                    if not recursive:
                        break
            time.sleep(1)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def join(self):
        if self._thread:
            self._thread.join(timeout=2)

class SentinelWatcher:
    def __init__(self, watch_dir: str, quarantine_dir: str = "quarantine"):
        self.watch_dir = os.path.abspath(watch_dir)
        self.inspector = FileInspector(quarantine_dir=quarantine_dir)
        self.event_handler = SentinelEventHandler(self.inspector)
        if HAS_WATCHDOG:
            self.observer = Observer()
        else:
            logger.info("Watchdog not installed. Using PollingObserver.")
            self.observer = PollingObserver()

    def start(self):
        logger.info(f"Starting Sentinel Watcher on directory: {self.watch_dir}")
        self.observer.schedule(self.event_handler, path=self.watch_dir, recursive=True)
        self.observer.start()

    def stop(self):
        logger.info("Stopping Sentinel Watcher...")
        self.observer.stop()
        self.observer.join()
