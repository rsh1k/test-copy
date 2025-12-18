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
    print("--- RUNNING AI ANALYSIS (HAIKU) ---")
    
    # 1. Load Trivy Data
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found.")
        sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # 2. Extract Vulnerabilities (Limit to top 15 for prompt efficiency)
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

    # 3. Call Claude with Haiku
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)
    selected_model = "claude-3-haiku-20240307"

    print(f"Requesting summary from: {selected_model}")
    try:
        prompt = (
            "As a security expert, analyze these vulnerabilities for a dotCMS environment. "
            "Provide a clear summary report with a table of CVEs, including 'Status' (TP/FP/Mitigated) "
            "and 'Security Controls'.\n\n"
            f"Vulnerabilities: {json.dumps(vulnerabilities[:15])}"
        )

        response = client.messages.create(
            model=selected_model,
            max_tokens=2500,
            messages=[{"role": "user", "content": prompt}]
        )
        report_text = response.content[0].text
    except Exception as e:
        print(f"API Error: {e}")
        sys.exit(1)

    # 4. Generate PDF Report
    output_path = "security_analysis_report.pdf"
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(0, 10, "dotCMS AI Security Analysis Report", ln=True, align='C')
    pdf.set_font("Helvetica", 'I', 10)
    pdf.cell(0, 10, f"Generated via Anthropic {selected_model}", ln=True, align='C')
    pdf.ln(10)
    
    # Body
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 7, clean_for_pdf(report_text))
    
    # Save to root (current working directory)
    pdf.output(output_path)
    print(f"Successfully generated: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    run_analysis()
