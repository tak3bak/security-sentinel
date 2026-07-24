import os
import time
import shutil
import logging
import threading
import requests
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Load environmental variables for beta release
load_dotenv()

# Mapping cleanly to your existing .env keys
WATCH_DIR = os.getenv("MONITORED_DIR", "./data")
QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", "./quarantine")
SPIDERFOOT_URL = os.getenv("SPIDERFOOT_API", "http://localhost:5001").rstrip("/")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

class SentinelHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.processed_files = {}
        self.lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        self.process_threat(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.process_threat(event.src_path)

    def process_threat(self, file_path):
        filename = os.path.basename(file_path)
        
        # Deduplication: Prevent processing duplicate event signals
        with self.lock:
            now = time.time()
            if filename in self.processed_files:
                if now - self.processed_files[filename] < 1.0:
                    return
            self.processed_files[filename] = now

        # Focus only on designated active-defense file targets
        if not filename.endswith((".malware", ".malwarere")):
            return

        # Race condition safety check
        if not os.path.exists(file_path):
            return

        logging.warning(f"[THREAT DETECTED] Malicious indicator matched: {filename}")
        
        # 1. Isolate/Quarantine File immediately
        quarantine_path = self.quarantine_file(file_path, filename)
        
        # Extract IP cleanly using dynamic slicing
        if filename.endswith(".malwarere"):
            ip_indicator = filename[:-10]
        elif filename.endswith(".malware"):
            ip_indicator = filename[:-8]
        else:
            ip_indicator = filename

        # 2. Async Threat Enrichment Pipeline
        enrichment_thread = threading.Thread(
            target=self.enrich_threat_data, 
            args=(ip_indicator, filename), 
            daemon=True
        )
        enrichment_thread.start()

    def quarantine_file(self, src_path, filename):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        unique_id = int(time.time())
        dest_path = os.path.join(QUARANTINE_DIR, f"isolated_{unique_id}_{filename}")
        try:
            shutil.move(src_path, dest_path)
            logging.info(f"[QUARANTINE] File contents safely isolated to: {dest_path}")
            return dest_path
        except Exception as e:
            logging.error(f"[QUARANTINE ERROR] Failed to move file: {e}")
            return None

    def enrich_threat_data(self, ip, filename):
        # --- Live Shodan Enrichment Pipeline ---
        if SHODAN_API_KEY and SHODAN_API_KEY != "your_shodan_api_key_here":
            logging.info(f"[SHODAN] Enriching threat indicator via API: {ip}")
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    isp = data.get('isp', 'Unknown ISP')
                    ports = data.get('ports', [])
                    logging.info(f"[SHODAN ALERT] Match found! ISP: {isp} | Ports Open: {ports}")
                elif response.status_code == 404:
                    logging.info(f"[SHODAN ALERT] No active records found for host {ip}")
                else:
                    logging.warning(f"[SHODAN ERROR] API returned status code {response.status_code}")
            except Exception as e:
                logging.error(f"[SHODAN EXCEPTION] Failed to connect to Shodan: {e}")
        else:
            logging.info(f"[SHODAN] API key missing or default. Skipping active lookup for: {ip}")

        # --- Live SpiderFoot v4 API Integration ---
        logging.info(f"[SPIDERFOOT] Initializing OSINT footprinting scan on target: {ip}")
        try:
            scan_name = f"Sentinel_Automated_{int(time.time())}"
            sf_endpoint = f"{SPIDERFOOT_URL}/startscan"
            
            # Structuring payload matching standard Spiderfoot form post conventions
            payload = {
                "scanname": scan_name,
                "scantarget": ip,
                "type": "all",              # Explicit scan type declaration
                "useprofile": "footprint",  # Use the standard low-overhead footprint profile
                "modulelist": "",           # Leave blank when using a defined profile template
                "typelist": ""
            }
            
            # Submitting scan request to local instance API with matching Content-Type headers
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(sf_endpoint, data=payload, headers=headers, timeout=5)
            
            # SpiderFoot successfully responds with a redirect or 200 OK when a scan is generated
            if response.status_code in [200, 302]:
                logging.info(f"[SPIDERFOOT SUCCESS] Automated scan initialization successful for target {ip}")
            else:
                logging.error(f"[SPIDERFOOT ERROR] Target endpoint API responded with status code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            logging.error(f"[SPIDERFOOT ERROR] Connection refused. Verify local SpiderFoot instance is running at {SPIDERFOOT_URL}")
        except Exception as e:
            logging.error(f"[SPIDERFOOT ERROR] API footprinting exception: {e}")

# --- Engine Runtime Execution ---
if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    logging.info("Initializing Hardened Active Defense Sentinel engine...")
    logging.info(f"Actively monitoring path: {WATCH_DIR}")

    event_handler = SentinelHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down Hardened Active Defense Sentinel engine...")
        observer.stop()
    observer.join()
