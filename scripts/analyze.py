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
                        "severity": v.get('Severity', '').upper()
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
                    "severity": v.get('severity', '').upper()
                })

    # 3. Parse Semgrep Results
    if os.path.exists('semgrep-results.json'):
        with open('semgrep-results.json', 'r') as f:
            try:
                data = json.load(f)
                for res in data.get('results', []):
                    raw_sev = res.get('extra', {}).get('severity', '').upper()
                    sev = "HIGH" if raw_sev in ["ERROR", "HIGH"] else raw_sev
                    vulnerabilities.append({
                        "source": "Semgrep",
                        "id": res.get('extra', {}).get('metadata', {}).get('cve', [res.get('check_id')])[0],
                        "pkg": f"File: {res.get('path')} (Line {res.get('start', {}).get('line')})",
                        "severity": sev
                    })
            except Exception as e:
                print(f"Warning: Semgrep parse failed: {e}")

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    # Deduplicate and Filter
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
    Perform a security analysis of these High/Critical CVEs against the dotCMS source code (https://github.com/dotCMS/core):
    {json.dumps(list(sorted_vulns)[:100])}

    MISSION: 
    Create a markdown table with: No., CVE name, OWASP Top 10, CVE Description, Validity, Likelihood, EPSS, CISA KEV and Impact on dotCMS.
    
    Above the table: provide count of each OWASP category.
    Validity: 'True Positive 👀' or 'False Positive ❌'.
    Likelihood: Short description based on EPSS/Kev/Reachability.
    End: Brief explanation of EPSS and CISA KEV.

    ONLY return markdown.
    """

    report_table = ""
    try:
        # Use .stream() to avoid the "10 minute" non-streaming restriction
        with client.messages.stream(
            model=MODEL_NAME,
            max_tokens=8000,
            system="You are a Senior Security Architect with expert knowledge of the dotCMS/core repository.",
            messages=[{"role": "user", "content": prompt}]
        ) as stream:
            for text in stream.text_stream:
                report_table += text
                # Optional: print(text, end="", flush=True) to see progress in Github logs
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
    
    print(f"Successfully updated {TARGET_FILE}")

if __name__ == "__main__":
    run_analysis()
