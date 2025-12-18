import json
import os
from anthropic import Anthropic
from fpdf import FPDF

def run_analysis():
    # 1. Load Trivy Results
    try:
        with open('trivy-results.json') as f:
            trivy_data = json.load(f)
    except FileNotFoundError:
        print("Trivy results not found.")
        return

    # 2. Load pom.xml for Context (Helping AI see project dependencies)
    pom_content = "Not available"
    if os.path.exists('pom.xml'):
        with open('pom.xml', 'r') as f:
            pom_content = f.read()[:5000] # Limit to first 5k chars for token efficiency

    # 3. Extract top vulnerabilities
    vulns = []
    results = trivy_data.get('Results', [])
    for res in results:
        for v in res.get('Vulnerabilities', []):
            vulns.append({
                "id": v.get('VulnerabilityID'),
                "package": v.get('PkgName'),
                "severity": v.get('Severity'),
                "description": v.get('Description', 'No description')[:300]
            })

    # 4. Prepare Claude Prompt
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    
    prompt = f"""
    You are a Senior Security Engineer. I have a Trivy scan for the dotCMS docker image.
    
    VULNERABILITIES FOUND:
    {json.dumps(vulns[:15], indent=2)}

    PROJECT CONTEXT (pom.xml snippet):
    {pom_content}

    TASK:
    1. Analyze if these CVEs are likely True Positives or False Positives in a dotCMS environment.
    2. Check if dotCMS's security architecture (Apache Shiro, Java filters) provides mitigating controls.
    3. Output a SUMMARY TABLE at the top with columns: CVE ID, Vulnerability, Status, Mitigating Control.
    4. Provide detailed reasoning for each entry.
    """

    print("Sending data to Claude...")
    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )

    full_text = message.content[0].text

    # 5. Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "DotCMS AI Vulnerability Analysis", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", size=10)
    # Using multi_cell to handle the table and text wrapping
    pdf.multi_cell(0, 8, full_text)
    
    pdf.output("security_analysis_report.pdf")
    print("Report generated: security_analysis_report.pdf")

if __name__ == "__main__":
    run_analysis()
