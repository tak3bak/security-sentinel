import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# Assuming you have an email_sender module
from email_sender import send_audit_email 

class AuditHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith("audit.md"):
            print(f"[!] New audit detected: {event.src_path}")
            # Extract client folder name
            folder = os.path.dirname(event.src_path)
            email_file = os.path.join(folder, "client_email.txt")
            
            if os.path.exists(email_file):
                with open(email_file, "r") as f:
                    email = f.read().strip()
                # Trigger the email process
                send_audit_email(email, event.src_path)
                print(f"[+] Email dispatched to {email}")

if __name__ == "__main__":
    path = "./audits"
    event_handler = AuditHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"[*] Monitoring {path} for new audits...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
