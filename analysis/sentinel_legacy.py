import os
import time
import hashlib
import re
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------------------------------------------
# Configuration & Logging Setup
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [SENTINEL-OPS] - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Target directory to monitor
TARGET_DIR = "./secure_zone"

# ---------------------------------------------------------
# Threat Intelligence: Leak Signatures (The "Ghosts")
# ---------------------------------------------------------
LEAK_PATTERNS = {
    "AWS_ACCESS_KEY": r"(?i)AKIA[0-9A-Z]{16}",
    "RSA_PRIVATE_KEY": r"-----BEGIN RSA PRIVATE KEY-----",
    "GENERIC_API_KEY": r"(?i)(api_key|apikey|secret|token)[\s:=]+['\"]?[0-9a-zA-Z]{16,}['\"]?",
    "HARDCODED_CREDENTIALS": r"(?i)(password|passwd|pwd)[\s:=]+['\"]?[^'\"]+['\"]?"
}

class SentinelEventHandler(FileSystemEventHandler):
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.file_hashes = {}
        self._initialize_baseline()

    def _initialize_baseline(self):
        logging.info("Initializing cryptographic baseline. Scanning for lurking threats...")
        if not os.path.exists(self.watch_directory):
            os.makedirs(self.watch_directory)
            
        for root, _, files in os.walk(self.watch_directory):
            for file in files:
                filepath = os.path.join(root, file)
                self.file_hashes[filepath] = self._calculate_hash(filepath)
        logging.info("Baseline established. Directory scanning is active at FULL PACE.")

    def _calculate_hash(self, filepath):
        """Generates a SHA-256 hash to detect file tampering."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except Exception as e:
            logging.error(f"Error hashing {filepath}: {e}")
            return None

    def _scan_for_leaks(self, filepath):
        """Scans file contents against known leak signatures."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for leak_type, pattern in LEAK_PATTERNS.items():
                    if re.search(pattern, content):
                        logging.critical(f"GHOST DETECTED! Potential {leak_type} leak exposed in: {filepath}")
        except Exception as e:
            logging.error(f"Read error during leak scan on {filepath}: {e}")

    def on_created(self, event):
        if not event.is_directory:
            logging.info(f"Anomaly: New file materialized -> {event.src_path}")
            self.file_hashes[event.src_path] = self._calculate_hash(event.src_path)
            self._scan_for_leaks(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            new_hash = self._calculate_hash(event.src_path)
            # Only trigger if the content actually changed (avoiding metadata-only triggers)
            if self.file_hashes.get(event.src_path) != new_hash:
                logging.warning(f"Integrity Alert: File modified -> {event.src_path}")
                self.file_hashes[event.src_path] = new_hash
                self._scan_for_leaks(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            logging.warning(f"File vanished from sector -> {event.src_path}")
            if event.src_path in self.file_hashes:
                del self.file_hashes[event.src_path]


def deploy_sentinel(target_directory):
    """Initializes and arms the watchdog observer."""
    event_handler = SentinelEventHandler(target_directory)
    observer = Observer()
    observer.schedule(event_handler, target_directory, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Manual override initiated. Sentinel standing down.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    logging.info("Booting Security Sentinel Ops...")
    # Ensure dependencies are met: pip install watchdog
    deploy_sentinel(TARGET_DIR)
