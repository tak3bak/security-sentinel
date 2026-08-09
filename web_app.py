import json
import os
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)
BASE_AUDIT_DIR = os.path.abspath("./audits")

@app.route('/audit', methods=['POST'])
def run_audit():
    data = request.json or {}
    domain = os.path.basename(str(data.get("domain", "")))
    email = str(data.get("email", ""))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    
    subprocess.Popen(["docker", "run", "--rm",
                      "-v", f"{BASE_AUDIT_DIR}:/app/audits",
                      "security-sentinel:latest", domain, email])
    return jsonify({"status": "started"})

@app.route('/status/<d>')
def get_status(d):
    safe_name = os.path.basename(str(d))
    target_path = os.path.abspath(os.path.join(BASE_AUDIT_DIR, safe_name, "progress.json"))
    
    # Enforce strict path traversal barrier
    if not target_path.startswith(BASE_AUDIT_DIR + os.sep):
        return jsonify({"error": "Unauthorized path access"}), 400
        
    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    return {"status": "init", "percent": 0}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
