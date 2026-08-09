import sys
import logging
from security_sentinel.main import start_security_sentinel


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("security_sentinel.log"),
        ],
    )


if __name__ == "__main__":
    setup_logging()
    logging.info("Starting Security Sentinel...")
    try:
        start_security_sentinel()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)
