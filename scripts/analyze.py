import json
import os
import sys
from anthropic import Anthropic

def run_analysis():
    # Configuration
    MODEL_NAME = "claude-sonnet-4-5"
    TARGET_FILE = "private_issue.md"
    TARGET_HEADING = "Security Analysis: High and Critical CVEs in dotCMS"
    
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
    
    # Filter for High and Critical only, then sort
    severity_map = {"CRITICAL": 0, "HIGH": 1}
    filtered_vulns = [v for v in unique_vulns if v['severity'].upper() in severity_map]
    sorted_vulns = sorted(filtered_vulns, key=lambda x: severity_map.get(x['severity'].upper(), 9))

    if not sorted_vulns:
        print("No High or Critical vulnerabilities found.")
        return

    # 3. Call Claude API
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not found in environment.")
        sys.exit(1)

    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a security analysis of these unique High/Critical CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(list(sorted_vulns)[:100])}

    MISSION: Create a markdown table with these exact columns: 
    No., CVE name, CVE type (OWASP), Description, Status, Likelihood of exploitability, and Explaination of Status.
    
    For these CVEs, analyze dotCMS core repo for compensating controls. 
    Status: 'True Positive' if vulnerable, 'False Positive' if not present/mitigated.
    Likelihood: Use EPSS, CISA KEV, code reachability, and attack complexity.
    
    ONLY return the markdown table. Do not include introductory or concluding text.
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

    # 4. Smart File Update (Preserving text above heading)
    if os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Find the line index of the heading
        header_index = -1
        for i, line in enumerate(lines):
            if TARGET_HEADING in line:
                header_index = i
                break
        
        if header_index != -1:
            # Slice file: keep everything UP TO and INCLUDING the heading line
            header_part = "".join(lines[:header_index + 1])
            new_content = f"{header_part.rstrip()}\n\n{report_table}\n"
        else:
            # If heading is missing, append it to the existing content
            existing_text = "".join(lines).rstrip()
            new_content = f"{existing_text}\n\n## {TARGET_HEADING}\n\n{report_table}\n"
    else:
        # Create new file if it doesn't exist
        new_content = f"# Security Report\n\n## {TARGET_HEADING}\n\n{report_table}\n"

    # Write the updated content
    with open(TARGET_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Successfully updated {TARGET_FILE} while preserving header text.")

if __name__ == "__main__":
    run_analysis()
