# sales_agent.py
from compliance_utils import generate_gap_analysis_pdf

def handle_onboarding_trigger(lead_data):
    # Logic to process lead
    if lead_data.get("needs_audit"):
        print(f"Generating assessment for {lead_data['name']}...")
        report_path = generate_gap_analysis_pdf(
            lead_data['name'], 
            lead_data['findings']
        )
        # Add logic here to email the file or send via your messaging API
        print(f"Report generated: {report_path}")
