import json
import os
import sys
from anthropic import Anthropic
from markdown_pdf import MarkdownPdf, Section

def run_analysis():
    # Official Claude 4.5 Sonnet ID
    MODEL_NAME = "claude-sonnet-4-5-20250929"
    print(f"--- STARTING AI ANALYSIS WITH {MODEL_NAME} ---")

    # 1. Load Trivy Data
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found."); sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # 2. Extract Vulnerabilities
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
        print("No vulnerabilities found to analyze."); return

    # 3. Request Analysis from Claude
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)

    try:
        # We ask Claude specifically for GitHub Flavored Markdown
        prompt = (
            "You are a Senior DevSecOps Engineer. Analyze these dotCMS vulnerabilities. "
            "IMPORTANT: Use GitHub Flavored Markdown. Include a professional table for the CVEs "
            "and use code blocks for remediation commands. "
            f"Data: {json.dumps(vulnerabilities[:15])}"
        )

        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=4000,
            system="Provide a high-quality security report in Markdown format with tables and code blocks.",
            messages=[{"role": "user", "content": prompt}]
        )
        report_md = response.content[0].text
    except Exception as e:
        print(f"API Error: {e}"); sys.exit(1)

    # 4. Generate Professional PDF
    # CSS to make the PDF look like a clean technical document
    custom_css = """
        body { font-family: 'Helvetica', sans-serif; line-height: 1.6; color: #333; }
        h1 { color: #1a365d; border-bottom: 2px solid #1a365d; padding-bottom: 10px; }
        h2 { color: #2c5282; margin-top: 25px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 12px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background-color: #f7fafc; font-weight: bold; }
        pre { background-color: #f8f9fa; border: 1px solid #e2e8f0; padding: 15px; border-radius: 5px; font-family: 'Courier', monospace; }
        code { font-family: 'Courier', monospace; background: #edf2f7; padding: 2px 4px; border-radius: 3px; }
    """

    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(report_md), user_css=custom_css)
    
    output_filename = "security_analysis_report.pdf"
    pdf.save(output_filename)
    print(f"Successfully generated formatted report: {output_filename}")

if __name__ == "__main__":
    run_analysis()
