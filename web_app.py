import json
import os
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/audit', methods=['POST'])
def run_audit():
    data = request.json or {}
    domain = os.path.basename(data.get("domain", ""))
    email = data.get("email", "")
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    subprocess.Popen(["docker", "run", "--rm",
                      "-v", f"{os.path.abspath('./audits')}:/app/audits",
                      "security-sentinel:latest", domain, email])
    return jsonify({"status": "started"})

@app.route('/status/<d>')
def get_status(d):
    safe_d = os.path.basename(d)
    path = os.path.join("./audits", safe_d, "progress.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {"status": "init", "percent": 0}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
