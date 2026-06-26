import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from security_sentinel.file_inspector import FileInspector

class SecuritySentinelHandler(FileSystemEventHandler):
    def __init__(self):
        self.inspector = FileInspector()

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(('.txt', '.log')):
            logging.info(f"File modified: {event.src_path}")
            self.inspector.inspect_file(event.src_path)

def start_watcher(monitored_dir):
    event_handler = SecuritySentinelHandler()
    observer = Observer()
    observer.schedule(event_handler, monitored_dir, recursive=False)
    logging.info(f"Security Sentinel active on: {monitored_dir}")
    observer.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()