#!/usr/bin/env python3
import sys
import os
import argparse

# Default seed list of high-intent target categories
SAMPLE_SEEDS = [
    ("nomadlist.com", "contact@nomadlist.com", "Nomad List"),
    ("remoteok.com", "security@remoteok.com", "RemoteOK"),
    ("postman.com", "security@postman.com", "Postman Inc"),
    ("resend.com", "support@resend.com", "Resend"),
    ("render.com", "security@render.com", "Render Services"),
    ("fly.io", "security@fly.io", "Fly.io"),
]

def append_targets(output_file: str, custom_entries=None):
    entries = custom_entries or SAMPLE_SEEDS
    
    with open(output_file, "a", encoding="utf-8") as f:
        for domain, email, company in entries:
            f.write(f"{domain}, {email}, {company}\n")
            
    print(f"[+] Appended {len(entries)} target prospects to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nomadik Sentinel - Lead Harvester")
    parser.add_argument("output_file", nargs="?", default="targets.txt", help="Destination targets file")
    args = parser.parse_args()
    
    append_targets(args.output_file)
