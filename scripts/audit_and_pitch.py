#!/usr/bin/env python3
import sys
import asyncio
import json
from app.osint import surface_scan

async def audit_and_generate_pitch(target_domain: str, prospect_email: str, company_name: str):
    print(f"\n[+] Running passive surface audit for {target_domain}...")
    try:
        scan_result = await surface_scan(target_domain)
    except Exception as e:
        print(f"[-] Scan error on {target_domain}: {str(e)}")
        return

    http_data = scan_result.get("http", {})
    sec_headers = http_data.get("security_headers", {})
    
    missing_headers = [h for h, val in sec_headers.items() if not val]
    present_headers = [h for h, val in sec_headers.items() if val]
    
    print("\n" + "="*70)
    print(f"EXECUTIVE SECURITY AUDIT: {company_name.upper()} ({target_domain})")
    print("="*70)
    print(f"HTTP Status:      {http_data.get('status_code', 'N/A')}")
    print(f"Server Header:    {http_data.get('server', 'Hidden / Cloudflare')}")
    print(f"Missing Headers:  {', '.join(missing_headers) if missing_headers else 'None (Fully Hardened)'}")
    print(f"Active Defenses:  {', '.join(present_headers) if present_headers else 'None Detected'}")
    
    print("\n" + "-"*70)
    print("TAILORED OUTBOUND PITCH COPY")
    print("-"*70)
    
    pitch = f"""Subject: Security posture audit for {company_name} — automated vulnerability monitoring

Hi {company_name} Team,

We ran a passive external surface check on {target_domain} and identified several perimeter hardening opportunities:

- Perimeter Exposure: {len(missing_headers)} critical security headers unconfigured ({', '.join(missing_headers[:3]) if missing_headers else 'standard audit'}).
- Risk Profile: Leaves client endpoints exposed to clickjacking, MIME-sniffing, and cross-site scripting (XSS) vectors.

Nomadik Security Sentinel provides continuous 24/7 autonomous threat detection, Wazuh alert ingestion, and perimeter auditing for your infrastructure.

Get onboarded with continuous monitoring in under 60 seconds:
👉 Starter Plan ($99/mo): https://nomadik.site/pricing?plan=starter&domain={target_domain}
👉 Professional Plan ($299/mo): https://nomadik.site/pricing?plan=pro&domain={target_domain}

Best regards,

Kalen Vandenbos
Systems Architect | Nomadik Security Operations
https://nomadik.site
"""
    print(pitch)
    print("="*70 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: PYTHONPATH=. python3 -m scripts.audit_and_pitch <domain> <prospect_email> <company_name>")
        print("Example: PYTHONPATH=. python3 -m scripts.audit_and_pitch example.com info@example.com 'Example Inc'")
        sys.exit(1)
        
    _, domain, email, company = sys.argv[:4]
    
    asyncio.run(audit_and_generate_pitch(domain, email, company))
