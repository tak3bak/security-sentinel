import os
import time
import logging
from logging.handlers import RotatingFileHandler
import json
from email.message import EmailMessage
from reporter import SecurityAuditGenerator

# Setup Log Rotation
log_file = os.path.join(os.path.dirname(__file__), "../dispatcher.log")
handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[handler],
)


def send_audit_email(client_dir, email_address, client_name):
    try:
        # ... (Existing logic to read JSON and generator) ...
        logging.info(f"Report dispatched to {email_address} for {client_name}")
    except Exception as e:
        logging.error(f"Failed to send email to {email_address}: {e}")


def monitor_audits():
    audit_base_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../audits")
    )
    logging.info("Dispatcher monitor started.")

    while True:
        if os.path.exists(audit_base_path):
            for client in os.listdir(audit_base_path):
                client_dir = os.path.join(audit_base_path, os.path.basename(client))
                # Only process if data exists and hasn't been "sent" (or reviewed)
                if (
                    os.path.isdir(client_dir)
                    and os.path.exists(os.path.join(client_dir, "data.json"))
                    and not os.path.exists(os.path.join(client_dir, "sent.txt"))
                ):

                    # Logic: Instead of sending email, just print that it's ready
                    print(f"[+] Audit ready for manual review: {client_dir}/audit.md")

                    # Optional: Automatically create the .md file so you can read it
                    # (Uses your existing generator logic)
                    # ... [Insert generator code here] ...

                    with open(os.path.join(client_dir, "sent.txt"), "w") as f:
                        f.write("reviewed")
        time.sleep(30)


if __name__ == "__main__":
    monitor_audits()
