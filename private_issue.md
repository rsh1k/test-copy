

| Number | Source | CVE Name | CVE Type (OWASP) | Description | Status |
|--------|--------|----------|------------------|-------------|--------|
| 1 | Trivy | CVE-2025-66516 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser vulnerability allowing arbitrary code execution through maliciously crafted PDF files. dotCMS uses Tika for content parsing and indexing without sandboxing. | ✔ |
| 2 | Trivy | CVE-2025-54988 | A06:2021 - Vulnerable and Outdated Components | Apache Tika PDF parser denial of service vulnerability through recursive PDF structure parsing. dotCMS exposes Tika parsing through content upload functionality. | ✔ |
| 3 | Trivy | CVE-2024-40094 | A03:2021 - Injection | GraphQL Java denial of service through deeply nested queries. dotCMS GraphQL API lacks query depth limiting controls in GraphQLServlet implementation. | ✔ |
| 4 | Trivy | CVE-2024-47072 | A08:2021 - Software and Data Integrity Failures | XStream deserialization vulnerability allowing remote code execution. dotCMS uses XStream for XML processing in workflow and configuration management without type restrictions. | ✔ |
| 5 | Trivy | CVE-2025-48734 | A08:2021 - Software and Data Integrity Failures | Apache Commons BeanUtils property injection vulnerability. dotCMS extensively uses BeanUtils in content API and form processing without input validation on property names. | ✔ |
| 6 | Trivy | CVE-2023-24998 | A01:2021 - Broken Access Control | Apache Commons FileUpload denial of service via unbounded file upload size. dotCMS implements size limits in UploadServlet but may have bypass paths through binary API. | ✔ |
| 7 | Trivy | CVE-2025-48976 | A04:2021 - Insecure Design | Apache Commons FileUpload path traversal in filename handling. dotCMS sanitizes filenames in FileAssetAPI but legacy upload handlers may lack validation. | ✔ |
| 8 | Trivy | CVE-2024-47554 | A01:2021 - Broken Access Control | Apache Commons IO path traversal vulnerability in file operations. dotCMS FileUtil and TempFileAPI use Commons IO without consistent path validation. | ✔ |
| 9 | Trivy | CVE-2024-25638 | A06:2021 - Vulnerable and Outdated Components | dnsjava key algorithm confusion vulnerability. dotCMS uses dnsjava for DNS lookups but has limited DNSSEC validation requirements in OSGi bundles. | ✔ |
| 10 | Trivy | GHSA-crjg-w57m-rqqf | A06:2021 - Vulnerable and Outdated Components | dnsjava DNSSEC validation bypass through crafted records. dotCMS DNS resolution in notification and email services doesn't enforce strict DNSSEC validation. | ✔ |
| 11 | Trivy | GHSA-mmwx-rj87-vfgr | A06:2021 - Vulnerable and Outdated Components | dnsjava cache poisoning vulnerability. dotCMS lacks DNS response validation controls in MailAPI and external service integrations. | ✔ |
| 12 | Trivy | CVE-2021-37136 | A06:2021 - Vulnerable and Outdated Components | Netty codec buffer overflow in Bzip2 decompression. dotCMS uses Netty in WebSocket and async HTTP clients without enforcing decompression limits. | ✔ |
| 13 | Trivy | CVE-2021-37137 | A06:2021 - Vulnerable and Outdated Components | Netty codec buffer overflow in Snappy decompression. dotCMS Netty usage in push publishing lacks compression size validation. | ✔ |
| 14 | Trivy | CVE-2012-6153 | A07:2021 - Identification and Authentication Failures | Apache HttpClient hostname verification vulnerability. dotCMS HttpClient usage in IntegrationResource and remote publishing may not enforce strict certificate validation. | ✔ |
| 15 | Trivy | CVE-2021-40690 | A02:2021 - Cryptographic Failures | Apache Santuario XML signature wrapping attack vulnerability. dotCMS SAML implementation uses xmlsec without sufficient signature validation controls. | ✔ |
