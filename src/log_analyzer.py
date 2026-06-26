import os

class LogAnalyzer:
    def __init__(self, log_path="/var/log/auth.log"):
        self.log_path = log_path

    def get_failed_attempts(self):
        if not os.path.exists(self.log_path):
            return 0
        try:
            with open(self.log_path, 'r', errors='ignore') as f:
                logs = f.readlines()
                return len([line for line in logs if "Failed password" in line])
        except PermissionError:
            return 0