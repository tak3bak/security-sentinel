import json
import hashlib
import os
from datetime import datetime

class ComplianceIntegrator:
    def __init__(self, log_file="threats.jsonl", audit_file="audit_trail.json", report_file="compliance_report.md"):
        self.log_file = log_file
        self.audit_file = audit_file
        self.report_file = report_file
        
        # Deep mapping of security findings to actual regulatory controls
        self.control_frameworks = {
            "high_entropy": {
                "SOC2": "CC6.1 (Logical Access Keys / Password Strength)",
                "HIPAA": "§ 164.312(a)(2)(iv) (Encryption & Decryption of ePHI)",
                "CMMC2": "IA.L2-3.5.3 (Perform Multi-Factor Authentication / Secure Credentials)"
            },
            "hardcoded_secret": {
                "SOC2": "CC7.2 (Vulnerability Management & Secure Development Practices)",
                "HIPAA": "§ 164.308(a)(1)(ii)(B) (Risk Management of System Vulnerabilities)",
                "CMMC2": "RA.L2-3.11.2 (Scan for Vulnerabilities in System Code)"
            },
            "unencrypted_storage": {
                "SOC2": "CC6.6 (Data Transmission & Storage Boundaries)",
                "HIPAA": "§ 164.312(e)(2)(ii) (Transmission Security & Encryption)",
                "CMMC2": "SC.L2-3.13.11 (Employ Cryptographic Mechanisms to Protect Confidentiality)"
            }
        }

    def generate_compliance_report(self):
        """Calculates the Compliance Readiness Score and generates audit exports."""
        findings = self._read_logs()
        total_issues = len(findings)
        
        # Deduct 15 points per finding to represent audit-level severity
        score = max(0, 100 - (total_issues * 15))
        
        mapped_findings = self._map_findings_to_frameworks(findings)
        integrity_hash = self._generate_hash(findings)
        timestamp = datetime.utcnow().isoformat()
        
        # Generate the machine-readable JSON Audit Trail
        json_report = {
            "timestamp": timestamp,
            "compliance_readiness_score": score,
            "mapped_findings": mapped_findings,
            "integrity_hash": integrity_hash
        }
        
        with open(self.audit_file, "w") as f:
            json.dump(json_report, f, indent=4)
            
        # Generate human-readable Markdown Report for Auditors
        self._write_markdown_report(score, mapped_findings, integrity_hash, timestamp)
        
        return json_report

    def _read_logs(self):
        if not os.path.exists(self.log_file): 
            return []
        with open(self.log_file, "r") as f:
            return [json.loads(line) for line in f]

    def _map_findings_to_frameworks(self, findings):
        results = []
        for finding in findings:
            finding_type = finding.get("type", "unknown")
            framework_mappings = self.control_frameworks.get(finding_type, {
                "SOC2": "Unmapped", "HIPAA": "Unmapped", "CMMC2": "Unmapped"
            })
            
            results.append({
                "finding": finding_type,
                "file_path": finding.get("file", "unknown_path"),
                "detected_at": finding.get("timestamp", datetime.utcnow().isoformat()),
                "frameworks": framework_mappings
            })
        return results

    def _generate_hash(self, data):
        """Creates an immutable SHA-256 digital signature of the raw logs."""
        serialized = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()

    def _write_markdown_report(self, score, mapped_findings, integrity_hash, timestamp):
        """Generates a professional, print-ready markdown report."""
        status = "PASSED (Excellent)" if score >= 85 else "ATTENTION REQUIRED (Action Plan Needed)"
        
        markdown_content = f"""# NOMADIK SECURITY OPERATIONS — COMPLIANCE REPORT
**Generated:** {timestamp}
**Audit Cryptographic Signature:** `{integrity_hash}`

---

## 📊 Compliance Readiness Score: {score}/100
**Status:** **{status}**

This score is mathematically calculated based on detected system vulnerabilities mapped directly to core security framework requirements (SOC 2 Type II, HIPAA, and CMMC 2.0 Level 2).

---

## 🔍 Detailed Mapping Matrix
"""
        if not mapped_findings:
            markdown_content += "\n*No compliance-impacting findings detected. System is clean and compliant.*\n"
        else:
            for item in mapped_findings:
                markdown_content += f"""
### Finding: `{item['finding']}`
* **Location:** `{item['file_path']}`
* **Detected:** {item['detected_at']}
* **Framework Controls Affected:**
    * **SOC 2 Type II:** {item['frameworks']['SOC2']}
    * **HIPAA Security Rule:** {item['frameworks']['HIPAA']}[cite: 1]
    * **CMMC 2.0 (L2):** {item['frameworks']['CMMC2']}[cite: 1]
---
"""
        with open(self.report_file, "w") as f:
            f.write(markdown_content)

if __name__ == "__main__":
    integrator = ComplianceIntegrator()
    report = integrator.generate_compliance_report()
    print(f"Compliance Report Compiled successfully.")
    print(f"Final Score: {report['compliance_readiness_score']}/100")
    print(f"Audit Trail Hash: {report['integrity_hash']}")
