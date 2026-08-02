import os
import shutil
import logging
import requests
from watchdog.events import FileSystemEventHandler

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

class SentinelHandler(FileSystemEventHandler):
    def process_event(self, src_path, dest_path):
        try:
            if not os.path.exists(src_path):
                return
            shutil.move(src_path, dest_path)
            logging.info("[QUARANTINE SUCCESS] Asset isolated securely under container")
        except Exception as e:
            logging.error(f"[QUARANTINE ERROR] Operational runtime fault: {type(e).__name__}")

    def enrich_threat_data(self, ip, mode_tag=""):
        if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_api_key_here":
            return
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": SHODAN_API_KEY}
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                isp = data.get('isp', 'Unknown ISP')
                ports = data.get('ports', [])
                logging.info(f"{mode_tag} [SHODAN ALERT] Match found! ISP: {isp} | Ports Open: {ports}")
            elif response.status_code == 404:
                logging.info(f"{mode_tag} [SHODAN ALERT] No active records found for host {ip}")
            else:
                logging.warning(f"{mode_tag} [SHODAN ERROR] API returned status code {response.status_code}")
        except Exception as e:
            logging.error(f"{mode_tag} [SHODAN EXCEPTION] Failed to connect to Shodan: {type(e).__name__}")
