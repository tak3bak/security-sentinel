import json
import os
import sys
import time
import shutil
from engine import SecurityEngine
from reporter import SecurityAuditGenerator
from log_analyzer import LogAnalyzer
from firewall import FirewallManager
from remediator import Remediator
from alerter import Alerter
from network_scanner import NetworkScanner
from dependency_scanner import DependencyScanner
from fim import FileIntegrityMonitor
from forensics_hunter import ForensicsHunter

def run_audit(domain, email):
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    audit_base_dir = os.path.join(base_path, "audits")
    client_dir = os.path.join(audit_base_dir, domain)
    quarantine_dir = os.path.join(base_path, "quarantine")
    os.makedirs(client_dir, exist_ok=True)
    
    # 1. Scanners & Hunters
    net_scanner = NetworkScanner()
    dep_scanner = DependencyScanner()
    fim = FileIntegrityMonitor(["/etc/passwd", "/etc/shadow"])
    hunter = ForensicsHunter(api_key="YOUR_SPIDERFOOT_KEY")
    
    # 2. Execution
    active_services = net_scanner.get_listening_services()
    dep_issues = dep_scanner.scan()
    integrity_alerts = fim.verify_integrity()
    
    # Identify attacker IPs from logs
    logger = LogAnalyzer()
    failed_ips = logger.get_brute_force_ips() # Assuming you add this to LogAnalyzer
    
    for ip in failed_ips:
        # If IP is persistent, hunt them
        hunt_results = hunter.hunt_attacker(ip)
        print(hunt_results)
    
    # 3. Remediation & Reporting
    engine = SecurityEngine()
    leaks = engine.run_directory_scan()
    remediator = Remediator(quarantine_dir)
    alerter = Alerter()
    
    for leak in leaks:
        if leak['severity'] == "CRITICAL":
            remediator.quarantine_file(leak['file'])
            alerter.send_alert(f"Quarantined: {leak['file']}")
            
    # ... (rest of the report generation logic remains the same)