import os
import re
import logging
from security_sentinel.config import LEAK_KEYWORDS, QUARANTINE_DIR
from security_sentinel.quarantine import QuarantineManager
from security_sentinel.spiderfoot import SpiderfootClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instantiate managers once to be used throughout the module
q_manager = QuarantineManager(QUARANTINE_DIR)
sf_client = SpiderfootClient()


def inspect_file(file_path):
    if not os.path.exists(file_path):
        logger.warning(f"File does not exist: {file_path}")
        return

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        # Detection of sensitive information
        for keyword in LEAK_KEYWORDS:
            if keyword in content:
                logger.warning(f"LEAK DETECTED: {file_path} ({keyword})")
                q_manager.quarantine_file(file_path)
                return

        # IP Extraction
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
        for ip in set(ips):
            logger.info(f"IP Found: {ip}. Triggering OSINT...")
            sf_client.trigger_scan(ip)

    except Exception as e:
        logger.error(f"Error inspecting file {file_path}: {e}")
