import json
import os
import sys
from anthropic import Anthropic
from markdown_pdf import MarkdownPdf, Section

def run_analysis():
    # Model ID for Claude 3.5/4.5 Sonnet
    MODEL_NAME = "claude-3-5-sonnet-20241022"
    
    # 1. Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found."); sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # Extract vulnerability data for the AI context
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": vuln.get('VulnerabilityID'),
                "severity": vuln.get('Severity'),
                "pkg": vuln.get('PkgName'),
                "installed": vuln.get('InstalledVersion')
            })

    # 2. Refined Security Researcher Prompt
    # This prompt follows your requirement to check the dotCMS source for mitigations
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    
    prompt = f"""
    You are a Senior Security Engineer performing a deep-dive audit. 
    Review these CVEs identified by Trivy: {json.dumps(vulnerabilities[:10])}

    YOUR MISSION:
    1. Cross-reference these CVEs with the dotCMS source code (https://github.com/dotCMS/core).
    2. Analyze specific functions (e.g., FileUtil.sanitizeFileName, ContentResource.java, SecurityLogger) to find existing mitigating or compensating controls.
    3. Categorize each finding as a "☑ TRUE POSITIVE" or "☑ FALSE POSITIVE" based on whether current code protects against it.
    
    REPORT STRUCTURE (MATCH scan.pdf EXACTLY):
    - Title: CVE ID & Package Name
    - Section: "Code-Based Evidence of Mitigations" including Java code snippets[cite: 39, 42].
    - Section: "Risk Assessment" table with columns: | Factor | Rating | Evidence Source |[cite: 89, 143].
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You have expert knowledge of the dotCMS/core repository and security architecture.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_md = response.content[0].text

    # 3. Apply Professional Styling (Matching scan.pdf)
    custom_css = """
        body { font-family: 'Helvetica', Arial, sans-serif; line-height: 1.6; color: #2d3748; padding: 40px; }
        h1 { color: #1a365d; border-bottom: 3px solid #1a365d; padding-bottom: 10px; }
        h2 { color: #2c5282; border-left: 6px solid #2c5282; padding-left: 15px; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th { background-color: #f7fafc; border: 1px solid #cbd5e0; padding: 12px; text-align: left; font-weight: bold; }
        td { border: 1px solid #cbd5e0; padding: 10px; font-size: 13px; }
        pre { background-color: #1a202c; color: #f7fafc; padding: 15px; border-radius: 6px; font-size: 11px; overflow-x: auto; }
        .status { font-weight: bold; color: #38a169; }
    """

    # 4. Save the PDF to a local folder for GitHub to commit
    os.makedirs("security-reports", exist_ok=True)
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(report_md), user_css=custom_css)
    pdf.save("security-reports/dotcms_validation_report.pdf")

if __name__ == "__main__":
    run_analysis()
