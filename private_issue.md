

# Security Analysis of CVEs in dotCMS/core

| Number | Source | CVE ID | CVE Type (OWASP) | Description | Status |
|--------|--------|--------|------------------|-------------|--------|
| 1 | Trivy | CVE-2025-66516 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser vulnerability allowing arbitrary code execution through malicious PDF files | ✔ |
| 2 | Trivy | CVE-2025-54988 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser vulnerability enabling denial of service via crafted PDF documents | ✔ |
| 3 | Trivy | CVE-2024-40094 | A03:2021 - Injection | GraphQL Java denial of service through deeply nested queries causing stack overflow | ✔ |
| 4 | Trivy | CVE-2024-47072 | A08:2021 - Software and Data Integrity Failures | XStream remote code execution via deserialization of untrusted XML data | ✔ |
| 5 | Trivy | CVE-2025-48734 | A08:2021 - Software and Data Integrity Failures | Commons BeanUtils arbitrary code execution through unsafe property population | ✔ |
| 6 | Trivy | CVE-2023-24998 | A01:2021 - Broken Access Control | Commons FileUpload denial of service via unlimited file size processing | ✔ |
| 7 | Trivy | CVE-2025-48976 | A01:2021 - Broken Access Control | Commons FileUpload path traversal vulnerability in file upload handling | ✔ |
| 8 | Trivy | CVE-2024-47554 | A01:2021 - Broken Access Control | Commons IO path traversal vulnerability in file operations allowing directory escape | ✔ |
| 9 | Trivy | CVE-2024-25638 | A06:2021 - Vulnerable and Outdated Components | DNSJava DNSSEC validation bypass allowing DNS spoofing attacks | ✔ |
| 10 | Trivy | GHSA-crjg-w57m-rqqf | A05:2021 - Security Misconfiguration | DNSJava KeyTrap denial of service through algorithmic complexity in DNSSEC validation | ✔ |
| 11 | Trivy | GHSA-mmwx-rj87-vfgr | A05:2021 - Security Misconfiguration | DNSJava resource exhaustion via malformed DNS responses | ✔ |
| 12 | Trivy | CVE-2021-37136 | A06:2021 - Vulnerable and Outdated Components | Netty Codec Bzip2 decoder out-of-bounds write vulnerability leading to RCE | ✔ |
| 13 | Trivy | CVE-2021-37137 | A06:2021 - Vulnerable and Outdated Components | Netty Codec Snappy decoder integer overflow causing denial of service | ✔ |
| 14 | Trivy | CVE-2012-6153 | A02:2021 - Cryptographic Failures | Apache HttpClient hostname verification bypass in SSL/TLS connections | ✔ |
| 15 | Trivy | CVE-2021-40690 | A02:2021 - Cryptographic Failures | Apache Santuario XML Security denial of service via exponential XML entity expansion | ✔ |
