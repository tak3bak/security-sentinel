import os
import re
import logging

from .config import MONITORED_DIR, LEAK_KEYWORDS
from .quarantine import quarantine_file
from .spiderfoot import trigger_spiderfoot

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def inspect_file(file_path):
    if not os.path.exists(file_path):
        logger.warning(f"File does not exist: {file_path}")
        return

    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # Detection of sensitive information
        for keyword in LEAK_KEYWORDS:
            if keyword in content:
                logger.warning(f"LEAK DETECTED: {file_path} ({keyword})")
                quarantine_file(file_path)
                return

        # IP Extraction
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
        for ip in set(ips):
            logger.info(f"IP Found: {ip}. Triggering OSINT...")
            trigger_spiderfoot(ip)

    except Exception as e:
        logger.error(f"Error inspecting file {file_path}: {e}")