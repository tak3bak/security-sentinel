import json
import os

def generate_compliance_report(log_file, compliance_db):
    """
    Merges sentinel log findings with compliance mapping.
    """
    report = []
    
    # Load your compliance mapping (e.g., HIPAA, SOC 2, CMMC 2.0)
    with open(compliance_db, 'r') as f:
        compliance_map = json.load(f)

    # Read the latest scan findings from your sentinel logs
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            for line in f:
                finding = json.loads(line)
                # Map finding to a control ID (assuming log contains 'threat_type')
                threat = finding.get("threat_type")
                control = compliance_map.get(threat, {"control": "N/A", "framework": "None"})
                
                finding["compliance_control"] = control
                report.append(finding)
    
    return report

# Output the report to a new JSONL file
def save_compliance_report(report, output_file):
    with open(output_file, 'w') as f:
        for entry in report:
            f.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    # Define your paths
    LOG_PATH = "sentinel_data/threats.jsonl"
    DB_PATH = "configs/compliance_map.json"
    OUTPUT = "audits/compliance_report.jsonl"
    
    os.makedirs("audits", exist_ok=True)
    
    data = generate_compliance_report(LOG_PATH, DB_PATH)
    save_compliance_report(data, OUTPUT)
    print(f"[+] Compliance report generated at {OUTPUT}")
