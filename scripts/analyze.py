import json
import os
import sys
import requests
from anthropic import Anthropic

# --- CONFIGURATION ---
MODEL_NAME = "claude-sonnet-4-5"
TARGET_FILE = "private_issue.md"
TARGET_HEADING = "Security Analysis: High and Critical CVEs in dotCMS"

def get_semgrep_findings(api_token, org_slug):
    """
    Pulls High/Critical findings from the Semgrep Cloud API.
    Docs: https://semgrep.dev/api/v1/docs/
    """
    print(f"--- Fetching findings from Semgrep Cloud ({org_slug}) ---")
    url = f"https://semgrep.dev/api/v1/deployments/{org_slug}/findings"
    headers = {"Authorization": f"Bearer {api_token}"}
    
    # We filter for 'unresolved' and high/critical severity to keep the AI focused
    params = {
        "issue_type": "sast",
        "state": "unresolved",
        "severity": ["high", "critical"]
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        external_vulns = []
        for finding in data.get('findings', []):
            # Extracting the most relevant info for Claude
            rule_id = finding.get('rule_name')
            file_path = finding.get('location', {}).get('file_path', 'unknown')
            line_num = finding.get('location', {}).get('line', '?')
            
            external_vulns.append({
                "source": "Semgrep Cloud",
                "id": rule_id,
                "pkg": f"File: {file_path} (Line {line_num})",
                "severity": finding.get('severity').upper(),
                "description": finding.get('rule_message', 'No description available.'),
                "link": finding.get('line_of_code_url', '')
            })
        print(f"Found {len(external_vulns)} findings in Semgrep Cloud.")
        return external_vulns
    except Exception as e:
        print(f"Warning: Failed to fetch Semgrep API data: {e}")
        return []

def run_analysis():
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
                        "severity": v.get('Severity', '').upper(),
                        "description": v.get('Description', '')
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
                    "severity": v.get('severity', '').upper(),
                    "description": v.get('description', '')
                })

    # 3. Pull from Semgrep Cloud API
    semgrep_token = os.environ.get("SEMGREP_API_TOKEN")
    semgrep_org = os.environ.get("SEMGREP_ORG_NAME")
    
    if semgrep_token and semgrep_org:
        cloud_findings = get_semgrep_findings(semgrep_token, semgrep_org)
        vulnerabilities.extend(cloud_findings)
    else:
        print("Skipping Semgrep Cloud: API token or Org name missing.")

    if not vulnerabilities:
        print("No vulnerabilities found in any scan.")
        return

    # Deduplicate and Filter for High/Critical
    unique_vulns = {v['id']: v for v in vulnerabilities if v['id']}.values()
    severity_map = {"CRITICAL": 0, "HIGH": 1}
    filtered_vulns = [v for v in unique_vulns if v['severity'] in severity_map]
    sorted_vulns = sorted(filtered_vulns, key=lambda x: severity_map.get(x['severity'], 9))

    if not sorted_vulns:
        print("No High or Critical vulnerabilities found.")
        return

    # 4. Call Claude API with Streaming
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not found.")
        sys.exit(1)

    client = Anthropic(api_key=api_key)
    
    prompt = f"""
    Perform a professional security analysis of these unique High/Critical vulnerabilities against the dotCMS repository.
    
    DATASET:
    {json.dumps(list(sorted_vulns)[:100])}

    MISSION: 
    Create a markdown table with these exact columns: 
    No., CVE name/Rule, OWASP Top 10, Description, Validity, Likelihood, EPSS, CISA KEV and Impact on dotCMS.
    
    INSTRUCTIONS:
    1. For Semgrep findings (SAST), analyze the specific file path provided for logic flaws.
    2. For Trivy/Scout findings (SCA), check if the library is used in a dangerous way in dotCMS core.
    3. Validity: 'True Positive 👁️' or 'False Positive ❌'.
    4. Provide an OWASP summary count at the top.
    5. Briefly explain EPSS and CISA KEV at the end.
    
    ONLY return markdown.
    """

    report_table = ""
    try:
        # Use streaming to prevent 10-minute timeout errors
        with client.messages.stream(
            model=MODEL_NAME,
            max_tokens=8000,
            system="You are a Lead Security Engineer expert in dotCMS and static/dynamic analysis.",
            messages=[{"role": "user", "content": prompt}]
        ) as stream:
            for text in stream.text_stream:
                report_table += text
    except Exception as e:
        print(f"Error calling Anthropic API: {e}")
        sys.exit(1)

    # 5. Update Target Markdown File
    if os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        
        if TARGET_HEADING in content:
            # Replace old table if header exists
            parts = content.split(f"## {TARGET_HEADING}")
            new_content = f"{parts[0].strip()}\n\n## {TARGET_HEADING}\n\n{report_table}\n"
        else:
            new_content = f"{content.strip()}\n\n## {TARGET_HEADING}\n\n{report_table}\n"
    else:
        new_content = f"# Security Report\n\n## {TARGET_HEADING}\n\n{report_table}\n"

    with open(TARGET_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Report successfully updated in {TARGET_FILE}")

if __name__ == "__main__":
    run_analysis()
