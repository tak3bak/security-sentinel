import datetime

class SecurityAuditGenerator:
    def __init__(self, client_name, scan_data):
        self.client_name = client_name
        self.scan_data = scan_data
        self.remediation_map = {
            "Stripe": "Revoke key in Stripe Dashboard and use environment variables.",
            "GitHub": "Revoke token immediately and rotate your credentials.",
            "SQL Injection Risk": "Use parameterized queries or ORM methods.",
            "Generic API Key": "Store in a secure vault like AWS Secrets Manager.",
            "AWS Access Key": "Rotate keys and use IAM roles instead of hardcoding.",
            "Private Key": "Delete from repo and rotate all associated certs.",
            "Potential Command Injection": "Avoid passing user input to system/subprocess calls."
        }

    def generate_markdown(self):
        leaks = self.scan_data.get('leaks', [])
        crit_count = sum(1 for l in leaks if l['severity'] == "CRITICAL")
        log_failures = self.scan_data.get('failed_logins', 0)
        network_services = self.scan_data.get('network_services', [])
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        report = f"# Security Posture Scorecard: {self.client_name}\n"
        report += f"**Date:** {timestamp}\n---\n\n"
        report += "## Executive Summary\n"
        report += "| Metric | Status |\n| :--- | :--- |\n"
        report += f"| **Security Risk Score** | {self.scan_data.get('risk_score', 100)}/100 |\n"
        report += f"| **Critical Leaks Detected** | {crit_count} |\n"
        report += f"| **Brute Force Attempts** | {log_failures} |\n\n"
        
        report += "## 1. Network Footprint (Listening Services)\n"
        for service in network_services:
            report += f"- `{service}`\n"
        
        report += "\n## 2. Identified Risks\n"
        for leak in leaks:
            report += f"- **[{leak['severity']}]** {leak['type']} in `{leak['file']}`\n"
            
        report += "\n## 3. Detailed Remediation Steps\n"
        for leak in leaks:
            report += f"- **{leak['type']}**: {self.remediation_map.get(leak['type'], 'Review best practices.')}\n"
            
        if log_failures > 5:
            report += "\n### ⚠️ Security Alert\nHigh number of failed login attempts detected. Check `/var/log/auth.log` and verify firewall settings.\n"
            
        return report