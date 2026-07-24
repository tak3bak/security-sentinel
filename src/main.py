import os
import subprocess
import json
import datetime
import math
from fastapi import FastAPI, BackgroundTasks, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from contextlib import asynccontextmanager

# --- Security Setup ---
API_KEY = "super-secret-nomadik-key"  # Change this for production!
API_KEY_NAME = "X-Sentinel-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
    )

# --- Entropy Logic ---
def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# --- Core Scan Logic ---
def perform_security_scan(target_path):
    for root, _, files in os.walk(target_path):
        for file in files:
            if file.endswith(('.txt', '.csv', '.json', '.log')):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                        if calculate_entropy(content) < 3.5:
                            threat = {
                                "timestamp": datetime.datetime.now().isoformat(),
                                "threat_type": "unencrypted_sensitive_file",
                                "file_path": full_path,
                                "details": "Low entropy detected: sensitive data likely unencrypted."
                            }
                            with open("sentinel_data/threats.jsonl", "a") as f:
                                f.write(json.dumps(threat) + "\n")
                except Exception as e:
                    print(f"Error scanning {full_path}: {e}")

# --- API & Pipeline ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs("sentinel_data", exist_ok=True)
    os.makedirs("audits", exist_ok=True)
    os.makedirs("configs", exist_ok=True)
    print("[*] Nomadik Security Sentinel initialized.")
    yield

app = FastAPI(title="Nomadik Security Sentinel", lifespan=lifespan)

class ScanRequest(BaseModel):
    target_path: str

def run_compliance_pipeline():
    try:
        subprocess.run(["python3", "src/compliance_integrator.py"], check=True)
    except Exception as e:
        print(f"[!] Pipeline error: {e}")

@app.post("/scan")
async def trigger_scan(scan: ScanRequest, background_tasks: BackgroundTasks, api_key: str = Security(get_api_key)):
    perform_security_scan(scan.target_path)
    background_tasks.add_task(run_compliance_pipeline)
    return {"status": "Scan complete. Compliance report generating."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
