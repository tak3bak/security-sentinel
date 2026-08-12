import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class QuarantineManager:
    def __init__(self, quarantine_dir=None):
        default_dir = os.getenv("QUARANTINE_DIR", "./security-sentinel/quarantine")
        self.quarantine_dir = os.path.abspath(quarantine_dir or default_dir)
        self.setup_quarantine_directory()

    def setup_quarantine_directory(self):
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            logging.info(f"Quarantine directory operational: {self.quarantine_dir}")
        except OSError as e:
            fallback = os.path.abspath("./quarantine_fallback")
            logging.warning(f"Failed to create {self.quarantine_dir} ({e}). Falling back to {fallback}")
            self.quarantine_dir = fallback
            os.makedirs(self.quarantine_dir, exist_ok=True)
