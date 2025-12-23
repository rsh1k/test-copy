import json
import os
import sys
from anthropic import Anthropic

def run_analysis():
    # Model ID as requested
    MODEL_NAME = "claude-sonnet-4-5"
    
    # Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found.")
        sys.exit(1)

    with open(trivy_file, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    # Extract vulnerabilities
    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        for v in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                "id": v.get('VulnerabilityID'),
                "pkg": v.get('PkgName'),
                "severity": v.get('Severity')
            })

    # Anthropic Client Setup
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set.")
        sys.exit(1)
        
    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a deep-dive security analysis of these CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(vulnerabilities[:10])}

    MISSION: Create a Markdown table with columns: Number, CVE name, CVE type (OWASP), Description, and Status (✔/✗).
    Analyze dotCMS core functions for compensating controls.
    If the vulnerability is present: ✔. If not: ✗.
    ONLY return the markdown table.
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_table = response.content[0].text

    # File logic
    target_file = "private_issue.md"
    marker = ""

    if not os.path.exists(target_file):
        print(f"Error: {target_file} not found. Creating it...")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(f"# Security Analysis\n\n{marker}\n")

    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    # The Replacement Logic
    if marker in content:
        # Keep everything before the marker, then add the marker and the new table
        header_part = content.split(marker)[0]
        new_content = f"{header_part}{marker}\n\n{report_table}\n"
    else:
        # Fallback: if marker is missing, append everything
        print("Marker not found in file. Appending to end.")
        new_content = f"{content}\n\n{marker}\n\n{report_table}\n"

    with open(target_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Successfully updated {target_file} using {MODEL_NAME}")

if __name__ == "__main__":
    run_analysis()
