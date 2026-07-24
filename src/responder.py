import os
import time
import redis
import requests
import subprocess
import json

# -----------------------------
# Redis Configuration
# -----------------------------
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = int(os.getenv("REDIS_PORT", 6379))
r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

# -----------------------------
# Wazuh Configuration
# -----------------------------
wazuh_url = os.getenv("WAZUH_API_URL")  # e.g. https://localhost:55000
wazuh_user = os.getenv("WAZUH_USER")    # e.g. admin
wazuh_pass = os.getenv("WAZUH_PASS")    # e.g. SecretPassword

print("[+] Security Sentinel Active Defense Engine Running...")


# -----------------------------
# IP Blocking Logic
# -----------------------------
def block_ip(ip):
    print(f"[+] Blocking IP: {ip}")
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    except Exception as e:
        print(f"[ERROR] iptables failed: {e}")


# -----------------------------
# Honeypot Event Processing
# -----------------------------
def process_honeypot_events():
    try:
        keys = r.keys("honeypot:ip:*")
        for key in keys:
            ip = key.split(":")[-1]
            print(f"[HONEYPOT] High-confidence attacker detected: {ip}")
            block_ip(ip)
            r.delete(key)
    except Exception as e:
        print(f"[ERROR] Honeypot scan failed: {e}")


# -----------------------------
# Wazuh JWT Authentication + Alert Fetch
# -----------------------------
def wazuh_get_alerts():
    try:
        if not wazuh_url or not wazuh_user or not wazuh_pass:
            print("[ERROR] Wazuh configuration missing (WAZUH_API_URL / WAZUH_USER / WAZUH_PASS)")
            return []

        # Step 1: Authenticate and get JWT token
        auth_payload = {
            "username": wazuh_user,
            "password": wazuh_pass
        }

        auth_resp = requests.post(
            f"{wazuh_url}/security/user/authenticate",
            json=auth_payload,
            verify=False
        )

        if auth_resp.status_code != 200:
            print(f"[ERROR] Wazuh authentication failed: {auth_resp.status_code} {auth_resp.text}")
            return []

        token = auth_resp.json().get("data", {}).get("token")

        if not token:
            print("[ERROR] Wazuh authentication failed: No token returned")
            return []

        headers = {
            "Authorization": f"Bearer {token}"
        }

        # -----------------------------
        # Correct Wazuh 4.x endpoint
        # -----------------------------
        alerts_resp = requests.get(
            f"{wazuh_url}/alerts/summary",
            headers=headers,
            verify=False
        )

        if alerts_resp.status_code != 200:
            print(f"[ERROR] Wazuh alerts fetch failed: {alerts_resp.status_code} {alerts_resp.text}")
            return []

        return alerts_resp.json()

    except Exception as e:
        print(f"[ERROR] Wazuh fetch failed: {e}")
        return []


# -----------------------------
# Main Loop
# -----------------------------
def run_responder():
    while True:
        process_honeypot_events()

        alerts = wazuh_get_alerts()
        if alerts:
            print("[WAZUH] Alerts received:")
            print(json.dumps(alerts, indent=2))

        time.sleep(2)


# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    run_responder()
