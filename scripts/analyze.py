import json
import os
import sys
from anthropic import Anthropic
from markdown_pdf import MarkdownPdf, Section

def run_analysis():
    # Model ID for Claude 4.5 Sonnet
    MODEL_NAME = "claude-sonnet-4-5-20250929"
    
    # 1. Load Scan Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found."); sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # 2. Extract Data for Claude
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": vuln.get('VulnerabilityID'),
                "severity": vuln.get('Severity'),
                "pkg": vuln.get('PkgName'),
                "description": vuln.get('Description', '')[:300]
            })

    # 3. Generate Report via Claude 4.5
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    
    prompt = (
        "Generate a dotCMS Security Analysis report. For each vulnerability: "
        "1. Check the source code at dotCMS github repo to find if there are any mitigating or compensating control available for the vulnerability. Go through each functions."
        "2.Use a clear header. "
        "2. Provide a 'Code-Based Evidence' section. "
        "3. Create a 'Risk Assessment' table with columns: 'Factor', 'Rating', and 'Evidence Source'. "
        "4. Use code blocks for any technical configuration. "
        f"Scan Data: {json.dumps(vulnerabilities[:10])}"
    )

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    report_md = response.content[0].text

    # 4. Apply Professional CSS Styling
    # This replicates the fonts and table styling seen in your scan.pdf
    custom_css = """
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.5; color: #2d3748; }
        h1 { color: #2b6cb0; border-bottom: 2px solid #2b6cb0; padding-bottom: 8px; margin-bottom: 20px; }
        h2 { color: #2c5282; margin-top: 30px; border-left: 4px solid #2c5282; padding-left: 10px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; background-color: #ffffff; }
        th { background-color: #edf2f7; color: #2d3748; border: 1px solid #cbd5e0; padding: 12px; text-align: left; font-weight: bold; }
        td { border: 1px solid #cbd5e0; padding: 10px; font-size: 13px; }
        pre { background-color: #1a202c; color: #f7fafc; padding: 15px; border-radius: 6px; font-family: 'Consolas', monospace; overflow-x: auto; }
        code { font-family: 'Consolas', monospace; background: #f7fafc; color: #e53e3e; padding: 2px 4px; border-radius: 4px; }
        .checkbox { color: #48bb78; font-weight: bold; }
    """

    # 5. Save as PDF
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(report_md), user_css=custom_css)
    pdf.save("dotcms_security_report.pdf")
    print("Report generated successfully.")

if __name__ == "__main__":
    run_analysis()
