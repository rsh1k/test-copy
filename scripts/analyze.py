import json
import os
import sys
from anthropic import Anthropic
from fpdf import FPDF

def clean_for_pdf(text):
    """Replaces characters that common PDF fonts can't handle."""
    replacements = {
        '\u2013': '-', '\u2014': '-', '\u2019': "'", 
        '\u2018': "'", '\u201d': '"', '\u201c': '"', '\u2022': '*'
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode('latin-1', 'replace').decode('latin-1')

def run_analysis():
    print("Starting AI Analysis (Free Tier Mode)...")
    
    # 1. Load Trivy Data
    if not os.path.exists('trivy-results.json'):
        print("Error: trivy-results.json not found.")
        sys.exit(1)

    with open('trivy-results.json') as f:
        trivy_data = json.load(f)

    # 2. Extract Vulnerabilities (Limiting to 10 for Free Tier)
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": vuln.get('VulnerabilityID'),
                "pkg": vuln.get('PkgName'),
                "severity": vuln.get('Severity'),
                "desc": vuln.get('Description', '')[:150]
            })

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    # 3. Call Claude with Haiku (Compatible with Free Tier)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)
    
    # Haiku is the most reliable model for the Free/Evaluation Tier
    selected_model = "claude-3-haiku-20240307"
    print(f"Requesting analysis using model: {selected_model}")

    try:
        response = client.messages.create(
            model=selected_model,
            max_tokens=2000,
            messages=[{
                "role": "user", 
                "content": f"Create a summary table for these dotCMS CVEs with status (TP/FP/Mitigated) and controls: {json.dumps(vulnerabilities[:10])}"
            }]
        )
        raw_content = response.content[0].text
    except Exception as e:
        print(f"API Error: {e}")
        sys.exit(1)

    # 4. Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", 'B', 14)
    pdf.cell(0, 10, "dotCMS AI Security Scan Report", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 7, clean_for_pdf(raw_content))
    pdf.output("security_analysis_report.pdf")
    print("Report generated successfully.")

if __name__ == "__main__":
    run_analysis()
