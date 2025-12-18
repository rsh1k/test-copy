# Update for model refresh
import json, os, sys
from anthropic import Anthropic
from fpdf import FPDF

def run_analysis():
    # MUST match your Tier 0 / Free Tier access
    MODEL_NAME = "claude-3-haiku-20240307"
    
    print(f"--- DEBUG: Attempting to call Anthropic with model: {MODEL_NAME} ---")
    
    if not os.path.exists('trivy-results.json'):
        print("Error: Scan file missing"); sys.exit(1)

    with open('trivy-results.json') as f:
        data = json.load(f)

    # Simplified summary for the free tier prompt
    vulns = []
    for res in data.get('Results', []):
        for v in res.get('Vulnerabilities', []):
            vulns.append(f"{v.get('VulnerabilityID')} ({v.get('PkgName')})")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)
    
    try:
        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=1000,
            messages=[{"role": "user", "content": f"Analyze these dotCMS vulns: {', '.join(vulns[:5])}"}]
        )
        report_text = response.content[0].text
    except Exception as e:
        print(f"--- API ERROR DETAIL --- \n{e}")
        sys.exit(1)

    # Simple PDF Creation
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt=report_text.encode('latin-1', 'ignore').decode('latin-1'))
    pdf.output("security_analysis_report.pdf")
    print("PDF Report successfully created.")

if __name__ == "__main__":
    run_analysis()
