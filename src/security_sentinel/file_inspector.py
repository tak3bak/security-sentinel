import os
import re
import json
import logging
from security_sentinel.quarantine import QuarantineManager

DEFAULT_LEAK_KEYWORDS = [
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "PRIVATE_KEY",
    "AKIAIOSFODNN7EXAMPLE"
]

try:
    from security_sentinel.config import LEAK_KEYWORDS
    # Filter out generic high-false-positive words if listed alone
    LEAK_KEYWORDS = [k.strip().upper() for k in LEAK_KEYWORDS if k.strip().upper() not in ["SECRET", "PASSWORD"]]
    LEAK_KEYWORDS = list(set(LEAK_KEYWORDS + DEFAULT_LEAK_KEYWORDS))
except ImportError:
    LEAK_KEYWORDS = DEFAULT_LEAK_KEYWORDS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class FileInspector:
    """
    Inspects target files for threats and automatically quarantines files matching leak criteria.
    """
    def __init__(self, quarantine_dir=None):
        self.q_manager = QuarantineManager(quarantine_dir)
        self.leak_keywords = LEAK_KEYWORDS

    def inspect_file(self, file_path: str) -> dict:
        if not os.path.exists(file_path):
            logging.error(f"Target file not found: {file_path}")
            return {
                "is_clean": False,
                "status": "error",
                "reason": "file_not_found",
                "file_path": file_path
            }

        file_size = os.path.getsize(file_path)
        logging.info(f"Inspecting file: {file_path} (size: {file_size} bytes)")

        detected_keyword = None
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read().upper()

            # 1. Match specific leak keywords
            for keyword in self.leak_keywords:
                if keyword in content:
                    detected_keyword = keyword
                    break

            # 2. Match structural secret patterns (e.g. key = value or bearer tokens)
            if not detected_keyword:
                secret_patterns = [
                    r'AWS_ACCESS_KEY_ID\s*=\s*\S+',
                    r'AWS_SECRET_ACCESS_KEY\s*=\s*\S+',
                    r'AKIA[0-9A-Z]{16}'
                ]
                for pat in secret_patterns:
                    if re.search(pat, content):
                        detected_keyword = pat
                        break

        except Exception as e:
            logging.error(f"Failed to read file {file_path}: {e}")
            return {
                "is_clean": False,
                "status": "error",
                "reason": f"read_error:{e}",
                "file_path": file_path
            }

        # If dirty or zero-byte, isolate and generate sidecar metadata
        if detected_keyword or file_size == 0:
            reason = f"leak_keyword_detected:{detected_keyword}" if detected_keyword else "zero_byte_file"
            logging.warning(f"File {file_path} failed inspection ({reason}). Quarantining...")
            
            quarantined_to = self.isolate_file(file_path, reason=reason)
            return {
                "is_clean": False,
                "status": "suspicious",
                "reason": reason,
                "file_path": file_path,
                "quarantined_to": quarantined_to
            }

        return {
            "is_clean": True,
            "status": "clean",
            "reason": "no_threats_detected",
            "file_path": file_path
        }

    def isolate_file(self, file_path: str, reason: str = "suspicious_file") -> str:
        filename = os.path.basename(file_path)
        dest = os.path.join(self.q_manager.quarantine_dir, f"isolated_{filename}")
        
        try:
            os.rename(file_path, dest)
            logging.info(f"Quarantined {file_path} -> {dest}")
            
            meta_path = f"{dest}.json"
            meta_data = {
                "original_file": file_path,
                "quarantined_file": dest,
                "reason": reason
            }
            with open(meta_path, "w") as mf:
                json.dump(meta_data, mf, indent=2)

            return dest
        except OSError as e:
            logging.error(f"Failed to quarantine file {file_path}: {e}")
            return ""

inspect_file = lambda path: FileInspector().inspect_file(path)
