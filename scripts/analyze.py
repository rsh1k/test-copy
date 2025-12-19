import json
import os
import sys
from anthropic import Anthropic
from markdown_pdf import MarkdownPdf, Section

def run_analysis():
    # Model ID for Claude 4.5
    MODEL_NAME = "claude-sonnet-4-5"
    
    # Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print("Trivy results not found."); sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    vulnerabilities = [
        {
            "id": v.get('VulnerabilityID'),
            "pkg": v.get('PkgName'),
            "severity": v.get('Severity')
        } for result in trivy_data.get('Results', []) for v in result.get('Vulnerabilities', [])
    ]

    # Initialize Claude 4.5
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    
    prompt = f"""
    Perform a deep-dive security analysis of these CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(vulnerabilities[:10])}

    YOUR MISSION: Create a table with four column: CVE name, CVE type, description and then the status(true/false,etc). Please note you have to go through each functions in the code and find out if compensating or mitigating controls are present or not.
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_md = response.content[0].text

    os.makedirs("security-reports", exist_ok=True)
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(report_md), user_css=custom_css)
    pdf.save("security-reports/dotcms_4.5_validation_report.pdf")

if __name__ == "__main__":
    run_analysis()
