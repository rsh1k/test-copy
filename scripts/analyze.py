import json
import os
import sys
from anthropic import Anthropic
from markdown_pdf import MarkdownPdf, Section

def run_analysis():
    # Model ID for Claude 4.5 Sonnet (Current stable version)
    MODEL_NAME = "claude-sonnet-4-5"
    
    # Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found.")
        sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # Flatten vulnerabilities list
    vulnerabilities = [
        {
            "id": v.get('VulnerabilityID'),
            "pkg": v.get('PkgName'),
            "severity": v.get('Severity')
        } for result in trivy_data.get('Results', []) for v in result.get('Vulnerabilities', [])
    ]

    # Initialize Anthropic Client
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)
        
    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a deep-dive security analysis of these CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(vulnerabilities[:10])}

    YOUR MISSION: Create a table with four columns: Number, CVE name, CVE type, description, and Status (True Positive/False Positive in checkmarks).
    Analyze the dotCMS core functions to determine if compensating or mitigating controls are present. I don't need full description, I just want the table.
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_md = response.content[0].text

    # PDF Generation - Removed custom_css
    os.makedirs("security-reports", exist_ok=True)
    pdf = MarkdownPdf(toc_level=2)
    
    # Passing only the Section without the user_css parameter
    pdf.add_section(Section(report_md)) 
    
    pdf.save("security-reports/dotcms_validation_report.pdf")
    print("Report generated: security-reports/dotcms_validation_report.pdf")

if __name__ == "__main__":
    run_analysis()
