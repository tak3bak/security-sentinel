import os
import re
import stat


class SecurityEngine:
    def __init__(self):
        self.severity_map = {
            "API Keys": "CRITICAL",
            "Infrastructure": "CRITICAL",
            "Critical Secrets": "CRITICAL",
            "Dangerous Patterns": "WARNING",
            "Network": "INFO",
            "Supply Chain": "WARNING",
            "System Integrity": "CRITICAL",
        }
        self.rules = {
            "API Keys": {
                "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
                "GitHub": r"ghp_[a-zA-Z0-9]{36}",
            },
            "Infrastructure": {
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "Private Key": r"-----BEGIN[A-Z ]+PRIVATE KEY-----",
            },
            "Dangerous Patterns": {
                "SQL Injection Risk": r"(?i)SELECT.*FROM.*WHERE.*=.*['\"].*\$.*",
                "Potential Command Injection": r"(?i)(os\.system|subprocess\.Popen)\s*\(\s*f?['\"]",
                "Reverse Shell Backdoor": r"(?i)(bash -i >& /dev/tcp/|nc -e /bin/bash)",
            },
        }

    def check_permissions(self, file_path):
        """Checks if a file is world-writable (e.g., 777)."""
        mode = os.stat(file_path).st_mode
        if mode & stat.S_IWOTH:
            return True
        return False

    def run_directory_scan(self):
        found_leaks = []
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target_dir = os.path.join(base_dir, "data")

        for root, _, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, os.path.basename(file))

                # Check 1: Content Patterns
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()
                        for category, patterns in self.rules.items():
                            for name, pattern in patterns.items():
                                if re.search(pattern, content):
                                    found_leaks.append(
                                        {
                                            "file": file_path,
                                            "category": category,
                                            "severity": self.severity_map.get(
                                                category, "INFO"
                                            ),
                                            "type": name,
                                        }
                                    )
                except Exception:
                    pass

                # Check 2: Permissions (New Logic)
                if self.check_permissions(file_path):
                    found_leaks.append(
                        {
                            "file": file_path,
                            "category": "System Integrity",
                            "severity": "CRITICAL",
                            "type": "World-Writable File",
                        }
                    )
        return found_leaks
