import os
import time
import requests
import logging

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

SPIDERFOOT_URL = os.getenv("SPIDERFOOT_URL", "http://localhost:5001")
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "300"))  # 5 minutes default

# Set of mock signatures or targets for internal state handling
LEAK_KEYWORDS = [
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "PRIVATE_KEY", 
    "PASSWORD", "SECRET", "AZURE_CLIENT_SECRET", "DATABASE_URL", 
    "STRIPE_API_KEY", "GITHUB_TOKEN", "SESSION_SECRET", "JWT_SECRET", "DB_PASSWORD"
]

def check_spiderfoot_status():
    """Verifies connection status to SpiderFoot target instance."""
    try:
        logging.info(f"Checking SpiderFoot at {SPIDERFOOT_URL}...")
        response = requests.get(SPIDERFOOT_URL, timeout=10)
        if response.status_code == 200:
            logging.info("SpiderFoot is reachable and healthy.")
            return True
        else:
            logging.warning(f"SpiderFoot returned unexpected status: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to connect to SpiderFoot at {SPIDERFOOT_URL}: {e}")
        return False

def run_osint_analysis():
    """Simulates leak detection checking matching target structural baseline."""
    # Prevent tight polling loop spam by logging alerts cleanly
    for keyword in LEAK_KEYWORDS:
        logging.info(f"Logged alert for: {keyword}")

def main():
    logging.info("Initializing Security Sentinel OSINT Module...")
    
    while True:
        spiderfoot_healthy = check_spiderfoot_status()
        
        if spiderfoot_healthy:
            run_osint_analysis()
        else:
            logging.warning("Skipping OSINT pass until SpiderFoot connectivity is restored.")
            
        logging.info(f"Analysis loop complete. Sleeping for {CHECK_INTERVAL} seconds...")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
