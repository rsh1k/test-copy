

# Security Analysis of CVEs against dotCMS Core

| Number | Source | CVE/Advisory | OWASP Category | Description | Status |
|--------|--------|--------------|----------------|-------------|---------|
| 1 | Trivy | CVE-2025-66516 | A06:2021 Vulnerable Components | Critical vulnerability in Apache Tika PDF parser module allowing potential remote code execution through maliciously crafted PDF files. dotCMS uses Tika for content extraction and PDF processing without sufficient sandboxing controls. | ✔ |
| 2 | Trivy | CVE-2025-54988 | A06:2021 Vulnerable Components | Critical vulnerability in Apache Tika PDF parser enabling XML External Entity (XXE) attacks through PDF metadata processing. dotCMS content ingestion pipeline processes PDFs without XXE protections. | ✔ |
| 3 | Trivy | CVE-2024-40094 | A03:2021 Injection | GraphQL query complexity validation bypass allowing DoS through deeply nested queries. dotCMS GraphQL API lacks adequate query depth limiting and complexity analysis controls. | ✔ |
| 4 | Trivy | CVE-2024-47072 | A08:2021 Software Integrity Failures | XStream deserialization vulnerability allowing remote code execution. dotCMS uses XStream for XML processing in REST APIs and content import/export without whitelist-based security configuration. | ✔ |
| 5 | Trivy | CVE-2025-48734 | A08:2021 Software Integrity Failures | Commons BeanUtils class introspection bypass enabling unauthorized property access. dotCMS reflection-based content manipulation uses BeanUtils without restricted class access controls. | ✔ |
| 6 | Trivy | CVE-2023-24998 | A01:2021 Broken Access Control | Commons FileUpload denial of service through unlimited file upload size. dotCMS file upload functionality relies on Commons FileUpload without enforced size limits at the parser level. | ✔ |
| 7 | Trivy | CVE-2025-48976 | A04:2021 Insecure Design | Commons FileUpload path traversal vulnerability in filename handling. dotCMS binary content upload does not sufficiently sanitize filenames before processing with Commons FileUpload. | ✔ |
| 8 | Trivy | CVE-2024-47554 | A01:2021 Broken Access Control | Commons IO path traversal in file operations allowing directory traversal attacks. dotCMS file system operations use Commons IO without canonical path validation. | ✔ |
| 9 | Trivy | CVE-2024-25638 | A06:2021 Vulnerable Components | DNSJava DNS cache poisoning vulnerability through insufficient validation. dotCMS uses DNSJava for DNS lookups in email and webhook functionality without DNSSEC validation. | ✔ |
| 10 | Trivy | GHSA-crjg-w57m-rqqf | A03:2021 Injection | DNSJava DNS rebinding attack vulnerability. dotCMS server-side request functionality uses DNSJava without DNS rebinding protections or allowlist validation. | ✔ |
| 11 | Trivy | GHSA-mmwx-rj87-vfgr | A05:2021 Security Misconfiguration | DNSJava improper certificate validation in DNS-over-HTTPS. dotCMS does not implement compensating certificate pinning or validation for DNS operations. | ✔ |
| 12 | Trivy | CVE-2021-37136 | A06:2021 Vulnerable Components | Netty codec buffer overflow in Bzip2 decompression leading to DoS. dotCMS uses Netty for HTTP/2 and WebSocket support without restricting decompression operations. | ✔ |
| 13 | Trivy | CVE-2021-37137 | A06:2021 Vulnerable Components | Netty codec HTTP request smuggling through improper header parsing. dotCMS reverse proxy configuration with Netty lacks header normalization controls. | ✔ |
| 14 | Trivy | CVE-2012-6153 | A02:2021 Cryptographic Failures | Apache HttpClient hostname verification bypass in SSL/TLS. dotCMS external HTTP integrations using HttpClient do not enforce strict hostname verification. | ✔ |
| 15 | Trivy | CVE-2021-40690 | A02:2021 Cryptographic Failures | Apache Santuario XML Signature wrapping attack vulnerability. dotCMS SAML authentication and XML signature validation lacks protection against signature wrapping attacks. | ✔ |
