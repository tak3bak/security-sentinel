# compliance_utils.py
from weasyprint import HTML

def generate_gap_analysis_pdf(client_name, findings):
    """
    Generates a PDF gap analysis report. 
    Findings should be a list of dictionaries: [{'domain': '...', 'status': '...', 'fix': '...'}]
    """
    rows = "".join([f"<tr><td>{f['domain']}</td><td>{f['status']}</td><td>{f['fix']}</td></tr>" for f in findings])
    
    html_content = f"""
    <html>
    <style>
        body {{ font-family: sans-serif; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
    <body>
        <h1>Gap Analysis: {client_name}</h1>
        <table>
            <tr><th>Domain</th><th>Status</th><th>Fix</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """
    filename = f"Gap_Analysis_{client_name.replace(' ', '_')}.pdf"
    HTML(string=html_content).write_pdf(filename)
    return filename
