import os
from dotenv import load_dotenv

load_dotenv()

MONITORED_DIR = os.getenv("MONITORED_DIR", "/app/data")
QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", "/app/quarantine")
LEAK_KEYWORDS = os.getenv("LEAK_KEYWORDS", "AWS_SECRET_ACCESS_KEY,PRIVATE_KEY,PASSWORD,SECRET").split(",")
SPIDERFOOT_API = os.getenv("SPIDERFOOT_API", "http://osint-spiderfoot:5001")
