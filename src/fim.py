import hashlib
import os

class FileIntegrityMonitor:
    def __init__(self, watch_list):
        self.watch_list = watch_list
        self.hash_file = "fim_hashes.json"

    def calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def verify_integrity(self):
        alerts = []
        # In a real scenario, compare current hashes against a stored JSON
        # This implementation flags existence of monitored files
        for file in self.watch_list:
            if not os.path.exists(file):
                alerts.append(f"CRITICAL: Monitored file missing: {file}")
        return alerts
