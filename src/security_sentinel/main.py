import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from security_sentinel.config import (
    MONITORED_DIR,
    QUARANTINE_DIR,
    LEAK_KEYWORDS,
    SPIDERFOOT_API,
)
from security_sentinel.file_inspector import FileInspector

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class SecuritySentinelHandler(FileSystemEventHandler):
    def __init__(self):
        self.inspector = FileInspector()

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith((".txt", ".log")):
            logging.info(f"File modified: {event.src_path}")
            self.inspector.inspect_file(event.src_path)


def main():
    observer = Observer()
    event_handler = SecuritySentinelHandler()
    observer.schedule(event_handler, MONITORED_DIR, recursive=False)
    logging.info(f"Security Sentinel active on: {MONITORED_DIR}")

    observer.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
