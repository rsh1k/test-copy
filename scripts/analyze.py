import json
import os
import sys
from anthropic import Anthropic

def run_analysis():
    # Model ID for Claude 4.5
    MODEL_NAME = "claude-sonnet-4-5" # Note: Use your preferred stable model ID
    
    # Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found.")
        sys.exit(1)

    with open(trivy_file) as f:
        trivy_data = json.load(f)

    # Flatten vulnerabilities list
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for v in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": v.get('VulnerabilityID'),
                "pkg": v.get('PkgName'),
                "severity": v.get('Severity')
            })

    # Initialize Anthropic Client
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)
        
    client = Anthropic(api_key=api_key)
    
    # Request analysis
    prompt = f"""
    Perform a deep-dive security analysis of these CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(vulnerabilities[:10])}

    YOUR MISSION: Create a Markdown table with four columns: Number, CVE name, CVE type (as per OWASP), Description, and Status (✔/✗).
    Analyze the dotCMS core functions to determine if compensating controls are present. 
    If the vulnerability is still present, the status should be ✔; if not present, it should be ✗.
    ONLY return the markdown table, no introductory text.
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_table = response.content[0].text

    # Target File Path
    target_file = "private_issue.md"

    # Append to the existing .md file
    if os.path.exists(target_file):
        with open(target_file, "a") as f:
            f.write("\n\n## Automated Security Analysis Table\n")
            f.write(f"Generated on: {os.popen('date').read()}\n\n")
            f.write(report_table)
            f.write("\n")
        print(f"Analysis appended to {target_file}")
    else:
        print(f"Error: {target_file} not found in the root directory.")
        sys.exit(1)

if __name__ == "__main__":
    run_analysis()
