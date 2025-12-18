import json
import os
import sys
from anthropic import Anthropic
from fpdf import FPDF

def run_analysis():
    # Official Claude 4.5 Sonnet ID
    MODEL_NAME = "claude-sonnet-4-5-20250929"
    
    print(f"--- INITIALIZING SECURITY ANALYSIS WITH {MODEL_NAME} ---")
    
    # 1. Load Data
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Critical Error: {trivy_file} not found."); sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # 2. Extract Vulns (Limiting context for efficiency)
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": vuln.get('VulnerabilityID'),
                "pkg": vuln.get('PkgName'),
                "severity": vuln.get('Severity'),
                "desc": vuln.get('Description', '')[:200]
            })

    if not vulnerabilities:
        print("Scan clean. No vulnerabilities to analyze."); return

    # 3. Call Claude 4.5
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    
    try:
        # Sonnet 4.5 excels at multi-step reasoning
        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=4000,
            system="You are a Senior DevSecOps Engineer specializing in dotCMS security.",
            messages=[{
                "role": "user", 
                "content": f"Analyze these dotCMS vulnerabilities. Check the dotCMS source code in the repo and find if there are any mitigating or compensating controls available for the CVEs. Provide a table with: CVE ID, Severity, Package, Status (True Positive/False Positive/Compensating Control Available, etc), and a Recommended Mitigation. Data: {json.dumps(vulnerabilities[:20])}"
            }]
        )
        report_text = response.content[0].text
    except Exception as e:
        print(f"API Error: {e}")
        print("Note: If 404/403, your Free Tier may not yet support Sonnet 4.5. Try claude-haiku-4-5-20251001.")
        sys.exit(1)

    # 4. Generate PDF Report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(0, 10, "dotCMS Security Analysis (Claude 4.5)", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Helvetica", size=10)
    
    # Cleaning text for latin-1 compatibility
    clean_text = report_text.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 7, clean_text)
    
    pdf.output("security_analysis_report.pdf")
    print(f"Report saved to root directory.")

if __name__ == "__main__":
    run_analysis()
