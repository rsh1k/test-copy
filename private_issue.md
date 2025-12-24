

# dotCMS Security Analysis - CVE Assessment

| Number | Source | CVE ID | OWASP Category | Description | Status |
|--------|--------|--------|----------------|-------------|--------|
| 1 | Trivy | CVE-2025-66516 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser module vulnerability allowing potential XXE or arbitrary code execution through maliciously crafted PDF files. dotCMS uses Tika for content extraction and indexing without input sanitization controls. | ✔ |
| 2 | Trivy | CVE-2025-54988 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser module DoS vulnerability through resource exhaustion when processing specially crafted PDF documents. No compensating controls found in dotCMS content processing pipeline. | ✔ |
| 3 | Trivy | CVE-2024-40094 | A03:2021 - Injection | GraphQL-Java ReDoS vulnerability in query parsing allowing denial of service through specially crafted queries. dotCMS GraphQL API endpoint exposed without query complexity limits or timeout controls. | ✔ |
| 4 | Trivy | CVE-2024-47072 | A08:2021 - Software and Data Integrity Failures | XStream deserialization vulnerability allowing remote code execution through untrusted XML input. dotCMS uses XStream for configuration serialization without allowlist-based type filtering. | ✔ |
| 5 | Trivy | CVE-2025-48734 | A08:2021 - Software and Data Integrity Failures | Commons-BeanUtils property injection vulnerability enabling arbitrary code execution through class loader manipulation. Used in dotCMS form processing without input validation. | ✔ |
| 6 | Trivy | CVE-2023-24998 | A01:2021 - Broken Access Control | Commons-FileUpload DoS vulnerability through unlimited file upload size leading to resource exhaustion. dotCMS implements partial file size limits but lacks comprehensive streaming controls. | ✔ |
| 7 | Trivy | CVE-2025-48976 | A04:2021 - Insecure Design | Commons-FileUpload path traversal vulnerability in filename handling allowing directory traversal attacks. dotCMS file upload API performs basic sanitization but vulnerable to encoded path sequences. | ✔ |
| 8 | Trivy | CVE-2024-47554 | A01:2021 - Broken Access Control | Commons-IO path traversal vulnerability in file operations allowing unauthorized file system access. dotCMS file system abstraction layer lacks comprehensive path canonicalization. | ✔ |
| 9 | Trivy | CVE-2024-25638 | A06:2021 - Vulnerable and Outdated Components | DNSJava DNS cache poisoning vulnerability through insufficient validation of DNS responses. Used by dotCMS for email delivery and external service resolution without DNSSEC validation. | ✔ |
| 10 | Trivy | GHSA-crjg-w57m-rqqf | A03:2021 - Injection | DNSJava DNS rebinding attack vulnerability allowing SSRF through malicious DNS responses. dotCMS lacks DNS response validation and TTL enforcement in external service calls. | ✔ |
| 11 | Trivy | GHSA-mmwx-rj87-vfgr | A05:2021 - Security Misconfiguration | DNSJava improper certificate validation in DNS-over-HTTPS/TLS implementations. dotCMS does not implement secure DNS transport layer controls. | ✔ |
| 12 | Trivy | CVE-2021-37136 | A06:2021 - Vulnerable and Outdated Components | Netty codec HTTP/2 request smuggling vulnerability through improper header validation. Used in dotCMS async HTTP clients for REST API integrations without header sanitization. | ✔ |
| 13 | Trivy | CVE-2021-37137 | A06:2021 - Vulnerable and Outdated Components | Netty codec HTTP request smuggling vulnerability via malformed Transfer-Encoding headers. dotCMS reverse proxy configurations lack smuggling detection mechanisms. | ✔ |
| 14 | Trivy | CVE-2012-6153 | A02:2021 - Cryptographic Failures | Apache HttpClient hostname verification bypass in SSL/TLS connections allowing MITM attacks. dotCMS uses HttpClient for external integrations without enforcing strict certificate validation. | ✔ |
| 15 | Trivy | CVE-2021-40690 | A02:2021 - Cryptographic Failures | Apache Santuario XMLSec XML signature wrapping vulnerability allowing signature bypass in SAML implementations. dotCMS SAML authentication relies on vulnerable signature validation. | ✔ |
