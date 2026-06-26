#!/bin/bash
# Set your SendGrid API Key here
export SENDGRID_API_KEY="YOUR_SENDGRID_API_KEY"

echo "[+] Starting Security Sentinel Suite..."

cd src
pkill -f email_dispatcher.py
nohup python3 email_dispatcher.py > ../dispatcher.log 2>&1 &
echo "[+] Email Dispatcher started."

python3 audit_runner.py example.com test@example.com
echo "[+] Scan completed."
