import requests
import logging
from requests.exceptions import RequestException
from security_sentinel.config import SPIDERFOOT_API

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SpiderfootClient:
    def __init__(self, api_url=SPIDERFOOT_API):
        self.api_url = api_url

    def trigger_scan(self, target):
        try:
            response = requests.post(
                f"{self.api_url}/api/scan/start", data={"target": target, "type": "IP"}
            )
            response.raise_for_status()
            logger.info(f"Triggered OSINT scan for IP: {target}")
            return response.json()
        except RequestException as e:
            logger.error(f"Failed to trigger scan for {target}: {e}")
            return None

    def check_scan_status(self, scan_id):
        try:
            response = requests.get(f"{self.api_url}/api/scan/status/{scan_id}")
            response.raise_for_status()
            logger.info(f"Scan status for {scan_id}: {response.json()}")
            return response.json()
        except RequestException as e:
            logger.error(f"Failed to check scan status for {scan_id}: {e}")
            return None

    def get_scan_results(self, scan_id):
        try:
            response = requests.get(f"{self.api_url}/api/scan/results/{scan_id}")
            response.raise_for_status()
            logger.info(f"Retrieved scan results for {scan_id}")
            return response.json()
        except RequestException as e:
            logger.error(f"Failed to retrieve scan results for {scan_id}: {e}")
            return None
