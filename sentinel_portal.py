from src.engine import run_directory_scan, perform_quarantine
from src.reporter import SecurityAuditGenerator

def run_public_audit(client_name):
    # 1. Same security task as the local utility
    leaks = run_directory_scan()
    for item in leaks:
        perform_quarantine(item['file'])
    
    # 2. Additional "Marketing" task that only the portal does
    scan_data = {'leaks': leaks, 'risk_score': 85} # ... etc
    gen = SecurityAuditGenerator(client_name, scan_data)
    # Save the audit.md and proposal.md ...