import re
import os
import difflib
from github import Github

# --- CONFIGURATION ---
# Replace with your actual "Organization/Repository"
REPO_NAME = "rsh1k/test-copy" 
SIMILARITY_THRESHOLD = 0.90
GITHUB_TOKEN = os.getenv("GH_TOKEN")
REPORT_PATH = "README.md"

def get_all_critical_findings(data):
    """
    Parses the README.md table to find rows marked as CRITICAL.
    """
    findings = []
    # Regex designed to match your specific table columns:
    # 1: No, 2: CVE/Rule, 3: OWASP, 4: Description, 5: Validity, 6: Likelihood/Severity
    pattern = r"(\d+)\s+([a-zA-Z0-9\.\-\_]+)\s+(A\d{2}:\d{4}.*?)\s+(.*?)\s+(True Positive.*?)\s+(CRITICAL)"
    
    matches = re.findall(pattern, data, re.MULTILINE)
    
    for m in matches:
        findings.append({
            "id": m[1],      # CVE name or Rule ID
            "owasp": m[2],
            "desc": m[3],
            "validity": m[4],
            "severity": m[5]
        })
    return findings

def is_too_similar(new_desc, existing_issues):
    """
    Checks if the new vulnerability description is 90% similar 
    to any currently open GitHub issue.
    """
    for issue in existing_issues:
        if not issue.body:
            continue
        # Compare the text content
        similarity = difflib.SequenceMatcher(None, new_desc, issue.body).ratio()
        if similarity >= SIMILARITY_THRESHOLD:
            return True, issue.number
    return False, None

def sync_vulnerabilities():
    # 1. Check for token
    if not GITHUB_TOKEN:
        print("Error: GH_TOKEN environment variable not set.")
        return

    # 2. Read README.md
    if not os.path.exists(REPORT_PATH):
        print(f"Error: {REPORT_PATH} not found.")
        return
    
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        scan_data = f.read()

    # 3. Extract Findings
    critical_findings = get_all_critical_findings(scan_data)
    if not critical_findings:
        print("No Critical vulnerabilities found in README.md.")
        return

    # 4. Connect to GitHub
    g = Github(GITHUB_TOKEN)
    try:
        repo = g.get_repo(REPO_NAME)
    except Exception as e:
        print(f"Error connecting to repo: {e}")
        return

    # 5. Process Findings
    # Fetch all open issues to prevent duplicates
    open_issues = list(repo.get_issues(state='open'))
    
    for vuln in critical_findings:
        issue_title = f"Security Critical: {vuln['id']}"
        
        # A. Exact ID Check (Title match)
        if any(vuln['id'] in issue.title for issue in open_issues):
            print(f"Skipping: {vuln['id']} (ID already exists in titles)")
            continue

        # B. Content Similarity Check (90% match)
        too_similar, issue_num = is_too_similar(vuln['desc'], open_issues)
        if too_similar:
            print(f"Skipping: {vuln['id']} (Content matches 90%+ with Issue #{issue_num})")
            continue

        # C. Create the Issue
        body = f"""## Critical Vulnerability Detected
- **Identifier:** {vuln['id']}
- **Severity:** {vuln['severity']}
- **OWASP Category:** {vuln['owasp']}
- **Validity:** {vuln['validity']}

### Description
{vuln['desc']}

---
*Automatically generated from README.md scan results.*"""

        try:
            new_issue = repo.create_issue(
                title=issue_title,
                body=body,
                labels=["security", "critical", "automated-scan"]
            )
            print(f"Successfully Created: {new_issue.html_url}")
            # Add to local list to prevent duplicate creation in the same run
            open_issues.append(new_issue)
        except Exception as e:
            print(f"Failed to create issue for {vuln['id']}: {e}")

if __name__ == "__main__":
    sync_vulnerabilities()
