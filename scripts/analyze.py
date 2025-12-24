import json
import os
import sys
from anthropic import Anthropic

def run_analysis():
    MODEL_NAME = "claude-sonnet-4-5"
    vulnerabilities = []

    # 1. Parse Trivy Results
    if os.path.exists('trivy-results.json'):
        with open('trivy-results.json', 'r') as f:
            data = json.load(f)
            for result in data.get('Results', []):
                for v in result.get('Vulnerabilities', []):
                    vulnerabilities.append({
                        "source": "Trivy",
                        "id": v.get('VulnerabilityID'),
                        "pkg": v.get('PkgName'),
                        "severity": v.get('Severity')
                    })

    # 2. Parse Docker Scout Results
    if os.path.exists('scout-results.json'):
        with open('scout-results.json', 'r') as f:
            data = json.load(f)
            # Docker Scout JSON structure varies slightly by version; 
            # this extracts CVEs from the typical 'vulnerabilities' array
            for v in data.get('vulnerabilities', []):
                vulnerabilities.append({
                    "source": "Scout",
                    "id": v.get('id'),
                    "pkg": v.get('package', {}).get('name'),
                    "severity": v.get('severity')
                })

    if not vulnerabilities:
        print("No vulnerabilities found in either scan.")
        return

    # Deduplicate by ID
    unique_vulns = {v['id']: v for v in vulnerabilities if v['id']}.values()
    # Sort by Severity (High/Critical first)
    severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(unique_vulns, key=lambda x: severity_map.get(x['severity'].upper(), 9))

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a security analysis of these unique CVEs (sourced from Trivy & Docker Scout) 
    against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(list(sorted_vulns)[:100])}

    MISSION: Create a markdown table with columns: No., CVE name, CVE type (OWASP), Description, Status, and Explaination of Status.
    For high and critical CVEs, analyze dotCMS core repo in Github. Check source codes for compensating controls. 
    If the vulnerability is present: True Positive. If not: False Positive in Status. 
    ONLY return the markdown table. Please only put CVEs with high and critical score in table. 
    """

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4000,
        system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
        messages=[{"role": "user", "content": prompt}]
    )
    report_table = response.content[0].text

    target_file = "private_issue.md"
    marker = ""

    if os.path.exists(target_file):
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = f"# dotCMS Security Analysis\n\n{marker}\n"

    marker_pos = content.find(marker)
    if marker_pos != -1:
        header = content[:marker_pos + len(marker)]
        new_content = f"{header}\n\n{report_table}\n"
    else:
        new_content = f"{content}\n\n{marker}\n\n{report_table}\n"

    with open(target_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Successfully updated {target_file} with combined scan data.")

if __name__ == "__main__":
    run_analysis()
