import os
import shutil
import logging

class QuarantineManager:
    def __init__(self, quarantine_dir):
        self.quarantine_dir = quarantine_dir
        self.setup_quarantine_directory()

    def setup_quarantine_directory(self):
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            logging.info(f"Quarantine directory created at: {self.quarantine_dir}")

    def quarantine_file(self, file_path):
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            destination = os.path.join(self.quarantine_dir, filename)
            shutil.move(file_path, destination)
            logging.warning(f"File quarantined: {filename}")
        else:
            logging.error(f"Attempted to quarantine non-existent file: {file_path}")