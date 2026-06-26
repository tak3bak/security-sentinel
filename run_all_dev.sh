#!/bin/bash
# Development Script: Testing new features
echo "[!] Running Development Suite with Severity Sorting and Remediation..."

# Move to src
cd src

# Run the scanner
python3 audit_runner.py dev-test-target dev@example.com

echo "[+] Dev Scan complete."
echo "[+] Previewing generated audit.md:"
cat ../audits/dev-test-target/audit.md