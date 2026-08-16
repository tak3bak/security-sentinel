#!/usr/bin/env python3
import os
import sys
import csv
import time
import smtplib
import argparse
import email.message

def dispatch_campaign(csv_file: str, dry_run: bool = True, delay_seconds: int = 5, min_exposure: int = 1):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if not dry_run and (not smtp_user or not smtp_pass):
        print("[-] Error: SMTP_USER and SMTP_PASS environment variables are required for live dispatch.")
        sys.exit(1)

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    actionable_rows = [r for r in rows if int(r.get("missing_headers_count", 0)) >= min_exposure]

    print(f"[+] Loaded {len(rows)} audits ({len(actionable_rows)} actionable with >= {min_exposure} missing headers)")
    print(f"[+] Execution Mode: {'DRY RUN (Preview Only)' if dry_run else 'LIVE DISPATCH'}\n")

    server = None
    if not dry_run:
        print(f"[+] Connecting to SMTP gateway {smtp_host}:{smtp_port}...")
        server = smtplib.SMTP_SSL(smtp_host, smtp_port)
        server.login(smtp_user, smtp_pass)

    for i, row in enumerate(actionable_rows, 1):
        company = row.get("company", "")
        domain = row.get("domain", "")
        recipient = row.get("email", "")
        missing_count = row.get("missing_headers_count", "0")
        pitch_text = row.get("pitch_body", "")

        lines = pitch_text.strip().split("\n")
        subject = lines[0].replace("Subject: ", "") if lines and lines[0].startswith("Subject:") else f"Security posture audit for {company}"
        body = "\n".join(lines[1:]).strip()

        print(f"[{i}/{len(actionable_rows)}] Target: {company} | Domain: {domain} | Exposure: {missing_count} missing headers")
        print(f"    Recipient: {recipient}")
        print(f"    Subject:   {subject}")

        if dry_run:
            print("    Status:    Ready for dispatch (Pass --send to execute)\n")
        else:
            msg = email.message.EmailMessage()
            msg["From"] = f"Kalen Vandenbos <{smtp_user}>"
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.set_content(body)

            try:
                server.send_message(msg)
                print(f"    [+] Status: DISPATCHED successfully.")
                time.sleep(delay_seconds)
            except Exception as e:
                print(f"    [-] Status: FAILED ({str(e)})")

    if server:
        server.quit()
        print("[+] Live campaign sequence completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nomadik Sentinel - Outbound Dispatcher")
    parser.add_argument("csv_file", nargs="?", default="outbound_campaign.csv", help="Path to campaign CSV file")
    parser.add_argument("--send", action="store_true", help="Execute live dispatch (default is dry-run)")
    parser.add_argument("--delay", type=int, default=5, help="Delay between emails in seconds (default: 5)")
    parser.add_argument("--min-exposure", type=int, default=1, help="Minimum missing headers required (default: 1)")
    args = parser.parse_args()

    dispatch_campaign(args.csv_file, dry_run=not args.send, delay_seconds=args.delay, min_exposure=args.min_exposure)
