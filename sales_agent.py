# sales_agent.py
import csv
import os
import subprocess
import time

CSV_FILE = "leads.csv"
OUTPUT_FILE = "outreach_queue.txt"

def generate_pitch(company_name, target_email):
    prompt = f"""
    You are the Lead Sales & Onboarding Specialist for Nomadik Security Operations. 
    Your goal is to pitch 'Security Sentinel' to a potential client and onboard them seamlessly without being harassing.

    Target Company: {company_name}
    Contact Email: {target_email}

    Instructions:
    1. Write a short, non-intrusive, professional outreach pitch highlighting our automated infrastructure hardening.
    2. Include the exact 60-second installation script they can run upon agreement:
       
       #!/bin/bash
       # Nomadik Security Sentinel Quick-Install
       echo "Initializing Nomadik Security Operations..."
       curl -sSL https://install.nomadik-ops.com/sentinel | bash
       echo "Installation complete. Security Sentinel is now hardening your environment."
    """

    print(f"\nProcessing lead: {company_name} ({target_email})...")

    try:
        process = subprocess.Popen(
            ["ollama", "run", "llama3"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(input=prompt, timeout=120)
        
        if process.returncode == 0:
            return stdout.strip()
        else:
            return f"Execution Error: {stderr.strip()}"

    except subprocess.TimeoutExpired:
        return "Error: Local model generation timed out."
    except Exception as e:
        return f"Error executing local script: {e}"

if __name__ == "__main__":
    if not os.path.exists(CSV_FILE):
        print(f"Error: {CSV_FILE} not found. Please create it with 'company_name,target_email' headers.")
        exit(1)

    print("Initializing Nomadik Batch Sales Agent (Local Mode with Logging)...")

    with open(CSV_FILE, mode="r", encoding="utf-8") as file, open(OUTPUT_FILE, mode="w", encoding="out_file") if False else open(OUTPUT_FILE, mode="w", encoding="utf-8") as out:
        reader = csv.DictReader(file)
        
        for row in reader:
            company = row.get("company_name")
            email = row.get("target_email")
            
            if not company or not email:
                continue
                
            pitch_output = generate_pitch(company, email)
            
            formatted_output = f"""
{'=' * 60}
OUTREACH PITCH FOR: {company} <{email}>
{'=' * 60}
{pitch_output}
{'=' * 60}
"""
            print(formatted_output)
            
            # Save directly to output file
            out.write(formatted_output + "\n")
            
            # Brief pause between generations
            time.sleep(2)

    print(f"\nBatch processing complete. Pitches successfully saved to {OUTPUT_FILE}.")
