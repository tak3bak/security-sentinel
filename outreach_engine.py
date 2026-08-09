import smtplib
import csv
import time
import random
import os
from email.message import EmailMessage

def send_outreach_email(recipient_email, client_name, company_name):
    # REPLACE THESE WITH YOUR ACTUAL CONFIGURATION
    sender_email = "your-email@example.com"
    password = os.getenv("SMTP_PASSWORD", "YOUR_APP_PASSWORD") 
    
    msg = EmailMessage()
    msg['Subject'] = f"Security Posture Check: {company_name}"
    msg['From'] = sender_email
    msg['To'] = recipient_email
    
    body = f"""Hi {client_name},

I'm a security architect at Nomadik Security Operations. We've built an automated Sentinel system that performs non-invasive security posture scans.

Most firms aren't aware of their 'Risk Score' until it's too late. I’d like to run a complimentary, automated audit for your external infrastructure and send you the scorecard—no strings attached.

Would you like me to add {company_name} to this week's scan schedule?

Best regards,
Nomadik Security Operations
"""
    msg.set_content(body)
    
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, password)
        smtp.send_message(msg)
    print(f"[+] Pitch sent to {recipient_email}")

def run_automated_outreach(csv_filename):
    if not os.path.exists(csv_filename):
        print(f"[!] Error: {csv_filename} not found.")
        return

    with open(csv_filename, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            print(f"[*] Processing {row['Company']}...")
            try:
                send_outreach_email(row['Email'], row['Name'], row['Company'])
                # Random sleep between 60 and 180 seconds to avoid spam filters
                wait_time = random.randint(60, 180)
                print(f"[*] Waiting {wait_time}s to maintain delivery reputation...")
                time.sleep(wait_time)
            except Exception as e:
                print(f"[!] Failed to send to {row['Email']}: {e}")

if __name__ == "__main__":
    run_automated_outreach('prospects.csv')