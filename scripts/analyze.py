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

    # Professional PDF Styling
    custom_css = """
        body { font-family: 'Helvetica', sans-serif; line-height: 1.5; padding: 40px; }
        h1 { color: #1a365d; border-bottom: 2px solid #1a365d; }
        h2 { color: #2c5282; margin-top: 30px; border-left: 5px solid #2c5282; padding-left: 10px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th { background-color: #f8fafc; border: 1px solid #cbd5e0; padding: 10px; text-align: left; }
        td { border: 1px solid #cbd5e0; padding: 10px; font-size: 13px; }
        pre { background-color: #1a202c; color: #f7fafc; padding: 15px; border-radius: 4px; font-size: 11px; }
    """

    os.makedirs("security-reports", exist_ok=True)
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(report_md), user_css=custom_css)
    pdf.save("security-reports/dotcms_4.5_validation_report.pdf")

if __name__ == "__main__":
    run_analysis()
