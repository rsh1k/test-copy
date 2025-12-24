import json
import os
import sys
from anthropic import Anthropic

def run_analysis():
    # Exact model name required
    MODEL_NAME = "claude-sonnet-4-5"
    
    # Load Trivy Results
    trivy_file = 'trivy-results.json'
    if not os.path.exists(trivy_file):
        print(f"Error: {trivy_file} not found.")
        sys.exit(1)

    with open(trivy_file, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    # Prepare data for Claude
    vulnerabilities = [
        {
            "id": v.get('VulnerabilityID'),
            "pkg": v.get('PkgName'),
            "severity": v.get('Severity')
        } for result in trivy_data.get('Results', []) for v in result.get('Vulnerabilities', [])
    ]

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set.")
        sys.exit(1)
        
    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a deep-dive security analysis of these CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(vulnerabilities[:10])}

    YOUR MISSION: Create a markdown table with columns: Number, CVE name, CVE type (OWASP), Description, and Status (✔/✗).
    Analyze dotCMS core functions for compensating controls. 
    If the vulnerability is present: ✔. If not: ✗.
    ONLY return the markdown table, no extra text.
    """

    try:
        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=4000,
            system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
            messages=[{"role": "user", "content": prompt}]
        )
        report_table = response.content[0].text
    except Exception as e:
        print(f"Error calling Anthropic API: {e}")
        sys.exit(1)

    target_file = "private_issue.md"
    marker = ""

    # Read current content safely
    if os.path.exists(target_file):
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = f"# dotCMS Security Analysis\n\n{marker}\n"

    # Logic: Keep everything BEFORE the marker, replace everything AFTER
    marker_pos = content.find(marker)
    if marker_pos != -1:
        # We found the marker. Keep it and cut off old data below it.
        header = content[:marker_pos + len(marker)]
        new_content = f"{header}\n\n{report_table}\n"
    else:
        # Marker missing, append it and the table
        new_content = f"{content}\n\n{marker}\n\n{report_table}\n"

    # Write back to file
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Successfully updated {target_file} using {MODEL_NAME}")

if __name__ == "__main__":
    run_analysis()
