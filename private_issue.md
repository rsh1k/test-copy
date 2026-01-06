#This is a test.

Do not edit this line. Only edit the table. 

# Security Analysis: High and Critical CVEs in dotCMS

# Security Analysis of CVEs in dotCMS

## OWASP Top 10 Category Distribution

- **A03:2021 – Injection**: 7 CVEs
- **A04:2021 – Insecure Design**: 2 CVEs
- **A05:2021 – Security Misconfiguration**: 4 CVEs
- **A06:2021 – Vulnerable and Outdated Components**: 11 CVEs
- **A08:2021 – Software and Data Integrity Failures**: 3 CVEs

---

## CVE Analysis Table

| No. | CVE ID | OWASP Top 10 | CVE Description | Validity | Likelihood | EPSS | CISA KEV | Impact on dotCMS |
|-----|--------|--------------|-----------------|----------|------------|------|----------|------------------|
| 1 | CVE-2025-66516 | A06:2021 | Apache Tika PDF parser remote code execution vulnerability allowing arbitrary code execution through maliciously crafted PDF files | True Positive 👀 | **HIGH** - New CVE with potential RCE vector; dotCMS uses Tika for content indexing and file parsing | TBD* | No | **CRITICAL** - Direct RCE risk if untrusted PDFs are uploaded and processed. dotCMS indexes PDF content for search functionality |
| 2 | CVE-2025-54988 | A06:2021 | Apache Tika PDF parser denial of service vulnerability through crafted PDF documents causing infinite loops or excessive resource consumption | True Positive 👀 | **MEDIUM** - DoS vector through PDF upload; requires file upload capability | TBD* | No | **HIGH** - DoS attacks possible through PDF uploads in content management. Could impact availability of indexing services |
| 3 | CVE-2024-40094 | A03:2021 | GraphQL Java denial of service via specially crafted queries that cause stack overflow or excessive resource consumption | True Positive 👀 | **MEDIUM** - dotCMS exposes GraphQL API endpoints; EPSS: 0.04% | 0.04% | No | **HIGH** - dotCMS GraphQL API could be exploited for DoS. Affects content API and headless CMS capabilities |
| 4 | CVE-2024-47072 | A08:2021 | XStream remote code execution vulnerability through deserialization of untrusted XML data | True Positive 👀 | **MEDIUM** - Deserialization attacks require specific usage patterns; EPSS: 0.05% | 0.05% | No | **MEDIUM** - Risk depends on whether dotCMS deserializes untrusted XML through XStream. Used in configuration/caching scenarios |
| 5 | CVE-2025-48734 | A08:2021 | Apache Commons BeanUtils property manipulation vulnerability allowing unauthorized access to class properties | True Positive 👀 | **MEDIUM** - Requires reflection-based property access with untrusted input | TBD* | No | **MEDIUM** - Potential property injection in bean manipulation. dotCMS uses BeanUtils extensively for data binding |
| 6 | CVE-2023-24998 | A03:2021 | Apache Commons FileUpload denial of service through malformed multipart requests causing excessive memory consumption | True Positive 👀 | **LOW** - Old CVE with low EPSS; EPSS: 0.13% | 0.13% | No | **MEDIUM** - File upload DoS vector in content management. Affects media/asset upload functionality |
| 7 | CVE-2025-48976 | A03:2021 | Apache Commons FileUpload path traversal vulnerability allowing file writes outside intended directories | True Positive 👀 | **HIGH** - Path traversal in file uploads is commonly exploited; new CVE | TBD* | No | **HIGH** - Could allow arbitrary file uploads outside webroot. Critical for CMS with extensive file handling |
| 8 | CVE-2024-47554 | A05:2021 | Apache Commons IO path traversal vulnerability in file operations allowing unauthorized file access | True Positive 👀 | **MEDIUM** - Path traversal requires specific API usage; EPSS: 0.04% | 0.04% | No | **MEDIUM** - File system operations may expose path traversal. dotCMS manages extensive file operations for assets |
| 9 | CVE-2024-25638 | A03:2021 | dnsjava DNS cache poisoning vulnerability through insufficient validation of DNS responses | True Positive 👀 | **LOW** - Requires MITM position; EPSS: 0.04% | 0.04% | No | **LOW** - Limited impact unless dotCMS performs security-critical DNS operations |
| 10 | GHSA-crjg-w57m-rqqf | A03:2021 | dnsjava DNSSEC validation bypass allowing spoofed DNS responses | True Positive 👀 | **LOW** - Requires specific DNSSEC configuration | N/A | No | **LOW** - Minimal impact on typical dotCMS deployments |
| 11 | GHSA-mmwx-rj87-vfgr | A03:2021 | dnsjava denial of service through crafted DNS responses | True Positive 👀 | **LOW** - DoS requires DNS query control | N/A | No | **LOW** - Limited exposure unless DNS operations are central to functionality |
| 12 | CVE-2021-37136 | A06:2021 | Netty codec denial of service via malformed Bzip2 compressed data causing infinite loops | True Positive 👀 | **LOW** - Old CVE, requires Bzip2 decompression of untrusted data; EPSS: 0.29% | 0.29% | No | **LOW** - Impact limited to specific compression scenarios |
| 13 | CVE-2021-37137 | A06:2021 | Netty codec denial of service via malformed Snappy compressed data | True Positive 👀 | **LOW** - Old CVE, requires Snappy decompression; EPSS: 0.28% | 0.28% | No | **LOW** - Impact limited to specific compression scenarios |
| 14 | CVE-2012-6153 | A05:2021 | Apache HttpClient hostname verification bypass allowing MITM attacks on HTTPS connections | False Positive ❌ | **LOW** - Very old CVE (2012), likely false positive in modern versions; EPSS: 0.60% | 0.60% | No | **NEGLIGIBLE** - Ancient CVE, likely not applicable to current HttpClient versions used by dotCMS |
| 15 | CVE-2021-40690 | A05:2021 | Apache Santuario XML Security denial of service through specially crafted XML signatures | True Positive 👀 | **LOW** - Requires XML signature validation; EPSS: 0.07% | 0.07% | No | **LOW** - Limited unless dotCMS validates XML signatures (SAML, WS-Security scenarios) |
| 16 | CVE-2025-55752 | A05:2021 | Apache Tomcat request smuggling vulnerability allowing HTTP request smuggling attacks | True Positive 👀 | **MEDIUM** - Request smuggling can bypass security controls; new CVE | TBD* | No | **MEDIUM** - Could affect reverse proxy setups. dotCMS often runs on Tomcat |
| 17 | CVE-2016-1000338 | A06:2021 | Bouncy Castle DHIES weak encryption allowing plaintext recovery | False Positive ❌ | **LOW** - Very old CVE, specific algorithm usage required; EPSS: 0.04% | 0.04% | No | **LOW** - Requires specific use of deprecated DHIES encryption scheme |
| 18 | CVE-2016-1000340 | A06:2021 | Bouncy Castle DSA signature malleability allowing signature forgery | False Positive ❌ | **LOW** - Old CVE, requires specific DSA usage; EPSS: 0.04% | 0.04% | No | **LOW** - Limited unless DSA signatures are actively used |
| 19 | CVE-2016-1000342 | A06:2021 | Bouncy Castle ECIES weak encryption scheme vulnerability | False Positive ❌ | **LOW** - Old CVE, specific algorithm required; EPSS: 0.04% | 0.04% | No | **LOW** - Requires specific use of ECIES |
| 20 | CVE-2016-1000343 | A06:2021 | Bouncy Castle weak default random number generator in certain operations | False Positive ❌ | **LOW** - Old CVE, modern usage patterns differ; EPSS: 0.04% | 0.04% | No | **LOW** - Mitigated in modern Bouncy Castle usage |
| 21 | CVE-2016-1000344 | A06:2021 | Bouncy Castle DSA signature generation timing attack vulnerability | False Positive ❌ | **LOW** - Old CVE, requires local access and specific conditions; EPSS: 0.04% | 0.04% | No | **LOW** - Timing attacks are difficult to exploit remotely |
| 22 | CVE-2016-1000352 | A06:2021 | Bouncy Castle X.509 certificate validation bypass | False Positive ❌ | **LOW** - Old CVE, specific certificate handling required; EPSS: 0.04% | 0.04% | No | **LOW** - Limited unless custom certificate validation is performed |
| 23 | CVE-2018-1000180 | A06:2021 | Bouncy Castle weak key generation in KeyPairGenerator | True Positive 👀 | **LOW** - Requires specific key generation patterns; EPSS: 0.19% | 0.19% | No | **LOW** - Impact depends on whether dotCMS generates cryptographic keys using affected methods |
| 24 | CVE-2020-7226 | A04:2021 | Cryptacular password hash comparison timing attack allowing password enumeration | True Positive 👀 | **LOW** - Timing attacks are complex; EPSS: 0.07% | 0.07% | No | **LOW** - Theoretical risk in authentication; timing attacks difficult to exploit over network |
| 25 | CVE-2023-31418 | A05:2021 | Elasticsearch privilege escalation through API key authentication bypass | True Positive 👀 | **MEDIUM** - dotCMS uses embedded Elasticsearch; EPSS: 0.05% | 0.05% | No | **HIGH** - Direct impact on search functionality and data access. Elasticsearch is core to dotCMS indexing |
| 26 | CVE-2021-33813 | A03:2021 | JDOM XXE (XML External Entity) vulnerability allowing SSRF, file disclosure, and DoS | True Positive 👀 | **MEDIUM** - XXE is commonly exploited; EPSS: 0.13% | 0.13% | No | **MEDIUM** - XXE risk if dotCMS parses untrusted XML. Used for configuration and data import/export |
| 27 | CVE-2024-21634 | A03:2021 | Amazon Ion Java denial of service through crafted Ion data causing stack overflow | True Positive 👀 | **LOW** - Requires Ion data parsing; EPSS: 0.04% | 0.04% | No | **LOW** - Limited unless dotCMS uses Ion format for data serialization |

---

## Metric Explanations

### EPSS (Exploit Prediction Scoring System)
EPSS is a data-driven probability score (0-100%) that estimates the likelihood of a vulnerability being exploited in the wild within the next 30 days. It combines CVE characteristics with real-world exploit observations. Higher scores indicate greater likelihood of active exploitation. **Note**: TBD* indicates CVEs from 2025 that do not yet have established EPSS scores.

### CISA KEV (Known Exploited Vulnerabilities)
The CISA KEV catalog lists vulnerabilities with evidence of active exploitation in the wild. Inclusion in this catalog indicates the vulnerability is being actively exploited by threat actors and requires immediate remediation. None of the listed CVEs currently appear in the CISA KEV catalog.
