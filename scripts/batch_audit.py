#!/usr/bin/env python3
import os
import sys
import csv
import asyncio
import argparse
from app.osint import surface_scan

async def process_target(semaphore, target_domain, prospect_email, company_name):
    async with semaphore:
        print(f"[+] Scanning {company_name} ({target_domain})...")
        try:
            scan = await surface_scan(target_domain)
            http_data = scan.get("http", {})
            headers = http_data.get("security_headers", {})
            missing = [h for h, v in headers.items() if not v]
            status_code = http_data.get("status_code", 0)
            server = http_data.get("server", "Hidden / Cloudflare")

            pitch = f"""Subject: Security posture audit for {company_name} — automated vulnerability monitoring

Hi {company_name} Team,

We ran a passive external surface check on {target_domain} and identified several perimeter hardening opportunities:

- Perimeter Exposure: {len(missing)} critical security headers unconfigured ({', '.join(missing[:3]) if missing else 'standard audit'}).
- Risk Profile: Leaves client endpoints exposed to clickjacking, MIME-sniffing, and cross-site scripting (XSS) vectors.

Nomadik Security Sentinel provides continuous 24/7 autonomous threat detection, Wazuh alert ingestion, and perimeter auditing for your infrastructure.

Get onboarded with continuous monitoring in under 60 seconds:
👉 Starter Plan ($99/mo): https://nomadik.site/pricing?plan=starter&domain={target_domain}
👉 Professional Plan ($299/mo): https://nomadik.site/pricing?plan=pro&domain={target_domain}

Best regards,

Kalen Vandenbos
Systems Architect | Nomadik Security Operations
https://nomadik.site"""

            return {
                "company": company_name,
                "domain": target_domain,
                "email": prospect_email,
                "status_code": status_code,
                "missing_headers_count": len(missing),
                "missing_headers": ", ".join(missing),
                "server": server,
                "pitch_body": pitch
            }
        except Exception as e:
            print(f"[-] Failed scan on {target_domain}: {str(e)}")
            return None

async def run_batch(input_file: str, output_csv: str, concurrency: int = 5):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3:
                domain, email, company = parts[:3]
                tasks.append(process_target(semaphore, domain, email, company))

    results = await asyncio.gather(*tasks)
    valid_results = [r for r in results if r]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "company", "domain", "email", "status_code", "missing_headers_count", "missing_headers", "server", "pitch_body"
        ])
        writer.writeheader()
        writer.writerows(valid_results)

    print(f"\n[+] Batch complete. {len(valid_results)} audits exported to: {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nomadik Security Sentinel - Batch Surface Auditor")
    parser.add_argument("input_file", nargs="?", default="targets.txt", help="Path to targets CSV/text file")
    parser.add_argument("output_file", nargs="?", default="outbound_campaign.csv", help="Path to output CSV file")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent scan workers")
    args = parser.parse_args()

    asyncio.run(run_batch(args.input_file, args.output_file, args.concurrency))
