import json
import os
from anthropic import Anthropic
from fpdf import FPDF

# 1. Parse Trivy Results
with open('trivy-results.json') as f:
    data = json.load(f)

# Focus on High/Critical vulnerabilities
vulnerabilities = []
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        if vuln['Severity'] in ['CRITICAL', 'HIGH']:
            vulnerabilities.append({
                "id": vuln['VulnerabilityID'],
                "pkg": vuln['PkgName'],
                "severity": vuln['Severity'],
                "desc": vuln['Description'][:200]
            })

# 2. Call Claude AI
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

# We feed Claude a sample of the repo structure so it knows where to "look"
prompt = f"""
You are an expert Security Engineer. I have performed a Trivy scan on the dotCMS docker image.
Found Vulnerabilities: {json.dumps(vulnerabilities[:15])}

Your Task:
1. Evaluate if these CVEs are actually exploitable in the dotCMS context. 
2. Consider that dotCMS uses Apache Shiro for security and has specific Java filters.
3. Check for mitigating controls (e.g., if a library is present but the vulnerable function is never called).
4. OUTPUT A TABLE first with columns: CVE ID, Package, Status (True Positive / False Positive / Mitigated), and Mitigating Control.
5. Follow the table with a detailed breakdown for each.
"""

message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=4000,
    messages=[{"role": "user", "content": prompt}]
)

# 3. Create PDF
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=11)
pdf.multi_cell(0, 8, message.content[0].text)
pdf.output("security_analysis_report.pdf")
