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

    # 1. Parse Trivy Results (SCA)
    if os.path.exists('trivy-results.json'):
        with open('trivy-results.json', 'r') as f:
            data = json.load(f)
            for result in data.get('Results', []):
                for v in result.get('Vulnerabilities', []):
                    vulnerabilities.append({
                        "source": "Trivy",
                        "id": v.get('VulnerabilityID'),
                        "pkg": v.get('PkgName'),
                        "severity": v.get('Severity', '').upper()
                    })

    # 2. Parse Docker Scout Results (SCA)
    if os.path.exists('scout-results.json'):
        with open('scout-results.json', 'r') as f:
            data = json.load(f)
            for v in data.get('vulnerabilities', []):
                vulnerabilities.append({
                    "source": "Scout",
                    "id": v.get('id'),
                    "pkg": v.get('package', {}).get('name'),
                    "severity": v.get('severity', '').upper()
                })

    # 3. Parse Semgrep Results (SAST)
    if os.path.exists('semgrep-results.json'):
        with open('semgrep-results.json', 'r') as f:
            try:
                data = json.load(f)
                for res in data.get('results', []):
                    # Semgrep uses 'ERROR' for high-severity findings
                    raw_sev = res.get('extra', {}).get('severity', '').upper()
                    sev = "HIGH" if raw_sev in ["ERROR", "HIGH"] else raw_sev
                    
                    vulnerabilities.append({
                        "source": "Semgrep",
                        "id": res.get('extra', {}).get('metadata', {}).get('cve', [res.get('check_id')])[0],
                        "pkg": f"File: {res.get('path')} (Line {res.get('start', {}).get('line')})",
                        "severity": sev,
                        "description": res.get('extra', {}).get('message')
                    })
            except Exception as e:
                print(f"Warning: Could not parse Semgrep results: {e}")

    if not vulnerabilities:
        print("No vulnerabilities found in any scan.")
        return

    # Deduplicate by ID
    unique_vulns = {v['id']: v for v in vulnerabilities if v['id']}.values()
    
    # Filter for High and Critical only
    severity_map = {"CRITICAL": 0, "HIGH": 1}
    filtered_vulns = [v for v in unique_vulns if v['severity'] in severity_map]
    sorted_vulns = sorted(filtered_vulns, key=lambda x: severity_map.get(x['severity'], 9))

    if not sorted_vulns:
        print("No High or Critical vulnerabilities found.")
        return

    # 4. Call Claude API
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not found in environment.")
        sys.exit(1)

    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a security analysis of these unique High/Critical vulnerabilities against the dotCMS source code (https://github.com/dotCMS/core).
    
    DATASET:
    {json.dumps(list(sorted_vulns)[:100])}

    MISSION: 
    Create a markdown table with these exact columns: 
    No., CVE name, OWASP Top 10, CVE Description, Validity, Likelihood of exploitability, EPSS, CISA KEV and Impact on dotCMS (explanation of Validity column + step by step analysis).
    
    INSTRUCTIONS:
    1. Above the table, provide a count of each OWASP category present.
    2. Analyze dotCMS core repo for compensating controls. 
    3. For Semgrep findings, focus on the specific file path provided.
    4. Validity: 'True Positive 👁️' if vulnerable, 'False Positive ❌' if not present/mitigated.
    5. Likelihood: Use EPSS, CISA KEV, code reachability, and attack complexity.
    6. At the end: Explain EPSS and CISA KEV briefly. 
    
    ONLY return the markdown content. No conversational filler.
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

    # 5. Smart File Update
    if os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        header_index = -1
        for i, line in enumerate(lines):
            if TARGET_HEADING in line:
                header_index = i
                break
        
        if header_index != -1:
            header_part = "".join(lines[:header_index + 1])
            new_content = f"{header_part.rstrip()}\n\n{report_table}\n"
        else:
            existing_text = "".join(lines).rstrip()
            new_content = f"{existing_text}\n\n## {TARGET_HEADING}\n\n{report_table}\n"
    else:
        new_content = f"# Security Report\n\n## {TARGET_HEADING}\n\n{report_table}\n"

    with open(TARGET_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Successfully updated {TARGET_FILE} with Trivy, Scout, and Semgrep findings.")

if __name__ == "__main__":
    run_analysis()
