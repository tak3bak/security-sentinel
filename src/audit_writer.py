import json
import datetime
import os

def log_finding(threat_type, file_path, details):
    """
    Writes a standardized finding to the Sentinel audit log.
    """
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "threat_type": threat_type,
        "file_path": file_path,
        "details": details
    }
    
    # Ensure the directory exists
    os.makedirs("sentinel_data", exist_ok=True)
    
    # Append to the log (JSONL format)
    with open("sentinel_data/threats.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"[+] Compliance-ready log entry written for: {threat_type}")
