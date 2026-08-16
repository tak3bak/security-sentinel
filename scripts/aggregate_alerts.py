#!/usr/bin/env python3
import os
import sqlite3

DB_PATH = os.getenv("SENTINEL_DB_PATH", os.getenv("DB_PATH", "data/telemetry_events.db"))

def analyze_detection_distribution():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database file not found at '{DB_PATH}'. Run telemetry ingestion or benchmark first.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. High-level telemetry counts
    cursor.execute("SELECT COUNT(*) FROM telemetry_events;")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_alerts;")
    total_alerts = cursor.fetchone()[0]

    # 2. Aggregation by MITRE ATT&CK Tag, Rule, and Severity
    cursor.execute("""
        SELECT 
            mitre_tag,
            rule_id,
            severity,
            title,
            COUNT(*) AS alert_count,
            COUNT(DISTINCT host_identifier) AS affected_hosts,
            COUNT(DISTINCT source_ip) AS unique_sources,
            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen
        FROM security_alerts
        GROUP BY mitre_tag, rule_id, severity
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            alert_count DESC;
    """)
    detection_rows = cursor.fetchall()

    # 3. Severity Distribution
    cursor.execute("""
        SELECT severity, COUNT(*) AS count
        FROM security_alerts
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END;
    """)
    severity_rows = cursor.fetchall()

    # 4. Host distribution
    cursor.execute("""
        SELECT host_identifier, COUNT(*) AS alert_count, COUNT(DISTINCT rule_id) AS distinct_rules
        FROM security_alerts
        GROUP BY host_identifier
        ORDER BY alert_count DESC
        LIMIT 5;
    """)
    host_rows = cursor.fetchall()

    conn.close()

    print("=" * 88)
    print(" Nomadik Security Sentinel - MITRE ATT&CK Detection Distribution")
    print("=" * 88)
    print(f" Database Target      : {DB_PATH}")
    print(f" Total Ingested Events: {total_events:,}")
    print(f" Total Alert Triggers : {total_alerts:,}")
    print(f" Global Trigger Rate  : {(total_alerts / total_events * 100) if total_events > 0 else 0:.2f}%")
    print("-" * 88)

    print("\n[+] Severity Distribution Breakdown:")
    for s in severity_rows:
        pct = (s['count'] / total_alerts * 100) if total_alerts > 0 else 0
        bar = "█" * int(pct / 4)
        print(f"  • {s['severity']:<10} : {s['count']:>6,} alerts ({pct:>5.1f}%) | {bar}")

    print("\n[+] Grouped by MITRE ATT&CK Technique & Sigma Rule:")
    header = f"{'MITRE TAG':<12} | {'RULE ID':<16} | {'SEVERITY':<10} | {'ALERTS':<8} | {'HOSTS':<6} | {'DETECTION TITLE'}"
    print(header)
    print("-" * 88)

    if not detection_rows:
        print("  No security alerts recorded in SQLite database.")
    else:
        for r in detection_rows:
            print(f"{r['mitre_tag']:<12} | {r['rule_id']:<16} | {r['severity']:<10} | {r['alert_count']:<8,} | {r['affected_hosts']:<6} | {r['title']}")

    print("\n[+] Top Targeted Host Sensors:")
    for h in host_rows:
        print(f"  • {h['host_identifier']:<28} : {h['alert_count']:>5,} alerts across {h['distinct_rules']} distinct rules")
    
    print("=" * 88 + "\n")

if __name__ == "__main__":
    analyze_detection_distribution()
