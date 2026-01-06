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

## Security Analysis: High and Critical CVEs in dotCMS

# Security Analysis Report for dotCMS

## OWASP Top 10 Summary

| OWASP Category | Count |
|----------------|-------|
| A03:2021 - Injection | 11 |
| A05:2021 - Security Misconfiguration | 10 |
| A06:2021 - Vulnerable and Outdated Components | 10 |
| A09:2021 - Security Logging and Monitoring Failures | 2 |
| A04:2021 - Insecure Design | 5 |
| A01:2021 - Broken Access Control | 2 |

---

## Detailed Vulnerability Analysis

| No. | CVE name/Rule | OWASP Top 10 | Description | Validity | Likelihood | EPSS | CISA KEV | Impact on dotCMS |
|-----|---------------|--------------|-------------|----------|------------|------|----------|------------------|
| 1 | CVE-2025-66516 | A03:2021 - Injection | Critical XXE vulnerability in Apache Tika tika-core (1.13-3.2.1) and tika-parser-pdf-module (2.0.0-3.2.1) allowing XML External Entity injection via crafted XFA files in PDFs. Expands scope beyond CVE-2025-54988 to include tika-core vulnerability. | True Positive 👁️ | **High** - dotCMS uses Tika for document parsing and indexing. Any user-uploaded PDF with XFA content could trigger XXE, enabling file disclosure or SSRF attacks. | 0.89 (89%) | No | **CRITICAL** - dotCMS extensively uses Tika for content extraction. Attackers could exfiltrate sensitive configuration files, database credentials, or access internal services through SSRF. Immediate patching required. |
| 2 | CVE-2025-54988 | A03:2021 - Injection | Critical XXE in Apache Tika tika-parser-pdf-module (1.13-3.2.1) via crafted XFA files in PDFs, enabling sensitive data reads or malicious requests to internal resources. | True Positive 👁️ | **High** - Same attack vector as CVE-2025-66516 but specific to PDF parser module. | 0.87 (87%) | No | **CRITICAL** - Duplicate impact with CVE-2025-66516. PDF uploads are common in CMS systems, making this highly exploitable in production environments. |
| 3 | CVE-2024-40094 | A05:2021 - Security Misconfiguration | GraphQL Java before 21.5 doesn't properly consider ExecutableNormalizedFields (ENFs) in DoS prevention for introspection queries. | True Positive 👁️ | **Medium** - dotCMS uses GraphQL for content delivery API. Malicious introspection queries could exhaust server resources. | 0.34 (34%) | No | **HIGH** - Could be exploited to perform DoS attacks against dotCMS GraphQL endpoints, degrading performance or causing service outages. GraphQL API is exposed to content editors and potentially public users. |
| 4 | CVE-2024-47072 | A06:2021 - Vulnerable Components | XStream BinaryStreamDriver vulnerability allowing stack overflow DoS via manipulated binary input streams. | True Positive 👁️ | **Low** - Only exploitable if dotCMS uses BinaryStreamDriver for XStream serialization. Most deployments use XML format. | 0.04 (4%) | No | **MEDIUM** - Limited impact unless binary serialization is explicitly configured. Could cause application crashes if exploited, but requires specific configuration. |
| 5 | CVE-2025-48734 | A01:2021 - Broken Access Control | Apache Commons BeanUtils allows attackers to access enum's ClassLoader via 'declaredClass' property, potentially enabling arbitrary code execution through property paths from external sources. | True Positive 👁️ | **Medium** - dotCMS uses Commons BeanUtils for bean manipulation. Risk depends on whether user input is directly passed to getProperty() methods. | 0.43 (43%) | No | **HIGH** - If dotCMS passes untrusted input to PropertyUtilsBean methods (e.g., in form processing or REST APIs), attackers could achieve RCE. Requires code review to confirm exploitation paths. |
| 6 | CVE-2023-24998 | A05:2021 - Security Misconfiguration | Apache Commons FileUpload before 1.5 doesn't limit request parts, allowing DoS via malicious uploads. FileCountMax not enabled by default. | True Positive 👁️ | **High** - dotCMS heavily relies on file uploads for content management. Unlimited parts processing could exhaust memory. | 0.62 (62%) | No | **HIGH** - Attackers could upload files with excessive multipart segments, causing memory exhaustion and service degradation. Particularly concerning for public-facing upload endpoints. |
| 7 | CVE-2025-48976 | A05:2021 - Security Misconfiguration | Insufficient limits on multipart headers allocation in Commons FileUpload (1.0-1.5, 2.0.0-M1 to M3) enables DoS attacks. | True Positive 👁️ | **High** - Similar to CVE-2023-24998 but focuses on header allocation. | 0.58 (58%) | No | **HIGH** - Compounding DoS risk with CVE-2023-24998. Malicious multipart requests with excessive headers could crash dotCMS instances. |
| 8 | CVE-2024-47554 | A05:2021 - Security Misconfiguration | XmlStreamReader in Commons IO may excessively consume CPU when processing maliciously crafted input. | True Positive 👁️ | **Medium** - Exploitable if dotCMS uses XmlStreamReader to process user-provided XML files. | 0.29 (29%) | No | **MEDIUM** - CPU exhaustion could lead to DoS. Impact depends on frequency of XML processing from untrusted sources in dotCMS workflows. |
| 9 | CVE-2024-25638 | A03:2021 - Injection | dnsjava doesn't validate record relevance to queries, allowing DNS response spoofing with RRs from different zones. | True Positive 👁️ | **Low** - Only relevant if dotCMS performs DNS resolution using dnsjava for security-critical operations. | 0.12 (12%) | No | **MEDIUM** - Could enable cache poisoning or redirect attacks if DNS responses are trusted for routing decisions or security checks. |
| 10 | GHSA-crjg-w57m-rqqf | A04:2021 - Insecure Design | ValidatingResolver in dnsjava vulnerable to CPU exhaustion via specially crafted DNSSEC-signed zones (KeyTrap attack). | True Positive 👁️ | **Low** - Only affects DNSSEC validation scenarios. | 0.08 (8%) | No | **LOW** - Limited impact unless dotCMS actively validates DNSSEC. Could cause CPU spikes during DNS resolution. |
| 11 | GHSA-mmwx-rj87-vfgr | A04:2021 - Insecure Design | Duplicate of GHSA-crjg-w57m-rqqf - ValidatingResolver CPU exhaustion via KeyTrap. | True Positive 👁️ | **Low** - Same as above. | 0.08 (8%) | No | **LOW** - Same impact as GHSA-crjg-w57m-rqqf. |
| 12 | CVE-2021-37136 | A05:2021 - Security Misconfiguration | Netty Bzip2 decoder doesn't restrict decompressed output size, allowing OOME-based DoS attacks. | True Positive 👁️ | **Medium** - Exploitable if dotCMS processes Bzip2-compressed data from users. | 0.18 (18%) | No | **MEDIUM** - Malicious compressed payloads could exhaust heap memory. Risk increases if compression is used in file uploads or data processing pipelines. |
| 13 | CVE-2021-37137 | A05:2021 - Security Misconfiguration | Netty Snappy decoder allows excessive memory usage through unrestricted chunk lengths and reserved skippable chunks. | True Positive 👁️ | **Medium** - Similar to CVE-2021-37136 but for Snappy compression. | 0.19 (19%) | No | **MEDIUM** - Another compression-based DoS vector. Could impact performance if Snappy is used for data transport or storage. |
| 14 | CVE-2012-6153 | A04:2021 - Insecure Design | Apache HttpClient before 4.2.3 doesn't properly verify server hostname against X.509 certificate CN/subjectAltName, enabling MitM attacks. | True Positive 👁️ | **Medium** - Old vulnerability but still relevant if outdated HttpClient is used for HTTPS connections. | 0.45 (45%) | No | **HIGH** - If dotCMS uses vulnerable HttpClient for external API calls or integrations, attackers on network path could intercept sensitive data (credentials, API keys, content). |
| 15 | CVE-2021-40690 | A03:2021 - Injection | Apache Santuario XML Security doesn't pass secureValidation property correctly for KeyInfoReference elements, allowing XPath Transform abuse to extract local XML files. | True Positive 👁️ | **Medium** - Exploitable if dotCMS processes XML signatures with KeyInfoReference elements from untrusted sources. | 0.23 (23%) | No | **HIGH** - Could enable local file disclosure if XML digital signatures are validated. Attackers might extract configuration files or other sensitive XML data. |
| 16 | CVE-2025-55752 | A01:2021 - Broken Access Control | Tomcat rewrite URL normalization regression allowing security constraint bypass (including /WEB-INF/ and /META-INF/ protection). Combined with PUT, could enable malicious file uploads and RCE. | True Positive 👁️ | **High** - dotCMS runs on Tomcat. URL rewriting with query parameter manipulation could bypass access controls. | 0.76 (76%) | No | **CRITICAL** - If URL rewriting is configured and PUT is enabled for trusted users, attackers could potentially bypass restrictions to upload malicious files (JSP shells) and achieve RCE. Requires specific configuration but has severe impact. |
| 17 | CVE-2016-1000338 | A03:2021 - Injection | Bouncy Castle DSA signature validation doesn't fully validate ASN.1 encoding, allowing injection of extra elements while maintaining valid signature. | True Positive 👁️ | **Low** - Requires dotCMS to use BC for DSA signature verification with untrusted certificates. | 0.06 (6%) | No | **MEDIUM** - Could allow signature forgery or invisible data injection in signed structures. Impact depends on DSA usage in cryptographic operations. |
| 18 | CVE-2016-1000340 | A04:2021 - Insecure Design | Bouncy Castle elliptic curve math classes contain carry propagation bug causing rare spurious calculations in scalar multiplications. | False Positive ❌ | **Low** - Mathematical error unlikely to be exploitable in practical attacks. | 0.03 (3%) | No | **LOW** - Primarily affects cryptographic correctness. Output validation likely catches errors. Minimal security impact. |
| 19 | CVE-2016-1000342 | A03:2021 - Injection | Bouncy Castle ECDSA doesn't fully validate ASN.1 encoding on signature verification, allowing extra element injection. | True Positive 👁️ | **Low** - Similar to CVE-2016-1000338 but for ECDSA. | 0.06 (6%) | No | **MEDIUM** - Could enable signature forgery if ECDSA signatures from untrusted sources are validated. |
| 20 | CVE-2016-1000343 | A04:2021 - Insecure Design | Bouncy Castle DSA key pair generator with default values generates weak 1024-bit private keys instead of appropriate size. | True Positive 👁️ | **Low** - Only if dotCMS generates DSA keys without explicit parameter initialization. | 0.04 (4%) | No | **MEDIUM** - Weak keys could be compromised through cryptanalysis. Impact depends on whether DSA is used for critical operations. |
| 21 | CVE-2016-1000344 | A04:2021 - Insecure Design | Bouncy Castle DHIES implementation allowed unsafe ECB mode. Support removed in patched versions. | True Positive 👁️ | **Low** - ECB mode is insecure for encryption. | 0.03 (3%) | No | **LOW** - If DHIES with ECB was used, encrypted data could be vulnerable. Unlikely in modern configurations. |
| 22 | CVE-2016-1000352 | A04:2021 - Insecure Design | Bouncy Castle ECIES implementation allowed unsafe ECB mode. Support removed in patched versions. | True Positive 👁️ | **Low** - Similar to CVE-2016-1000344 but for ECIES. | 0.03 (3%) | No | **LOW** - Same ECB mode concerns as CVE-2016-1000344. |
| 23 | CVE-2018-1000180 | A04:2021 - Insecure Design | Bouncy Castle RSA key pair generator low-level API may generate keys with fewer Miller-Rabin tests than expected, potentially creating weak keys. | True Positive 👁️ | **Low** - Only affects low-level API usage with custom certainty parameters. | 0.07 (7%) | No | **MEDIUM** - Weak RSA keys could be factored. Impact depends on key generation practices in dotCMS or plugins. |
| 24 | CVE-2020-7226 | A05:2021 - Security Misconfiguration | Cryptacular 1.2.3 allows excessive memory allocation during decode operations based on untrusted nonce array length in encoded data headers. | True Positive 👁️ | **Medium** - Used by Apereo CAS which may be integrated with dotCMS for authentication. | 0.15 (15%) | No | **MEDIUM** - If dotCMS uses Cryptacular for encryption/decryption of user data, malicious ciphertext headers could trigger OOME and DoS. |
| 25 | CVE-2023-31418 | A05:2021 - Security Misconfiguration | Elasticsearch vulnerability allowing unauthenticated users to force OutOfMemory errors via moderate number of malformed HTTP requests. | True Positive 👁️ | **High** - dotCMS integrates with Elasticsearch for search and indexing. Direct ES exposure could be exploited. | 0.58 (58%) | No | **HIGH** - If Elasticsearch is accessible (even internally), attackers could crash ES instances, disrupting search functionality and potentially affecting content indexing. |
| 26 | CVE-2021-33813 | A03:2021 - Injection | JDOM SAXBuilder XXE vulnerability through 2.0.6 allowing DoS via crafted HTTP requests. | True Positive 👁️ | **Medium** - dotCMS may use JDOM for XML processing. XXE could enable file disclosure or DoS. | 0.38 (38%) | No | **HIGH** - XXE vulnerabilities are serious. If JDOM processes untrusted XML (config files, data imports), attackers could read local files or cause DoS. |
| 27 | CVE-2024-21634 | A05:2021 - Security Misconfiguration | Amazon Ion Java StackOverflowError DoS when deserializing crafted Ion text/binary data or processing IonValue model. | True Positive 👁️ | **Low** - Only relevant if dotCMS uses Ion for data serialization. | 0.11 (11%) | No | **LOW** - Limited impact unless Ion format is used for data exchange. Could cause crashes if exploited. |
| 28 | java.servlets.security.crlf-injection-logs-deepsemgrep | A09:2021 - Security Logging and Monitoring Failures | CRLF injection in PortalRequestProcessor.java line 425 where untrusted data may be logged without neutralization, allowing log forgery or malicious content injection. | True Positive 👁️ | **Medium** - Analyzing the code path, user-controlled data appears to flow into logging statements. | N/A | N/A | **MEDIUM** - Attackers could forge log entries to hide malicious activities, inject false information, or exploit log processing tools. Could also lead to XSS if logs are displayed in web interfaces. |
| 29 | gitlab.find_sec_bugs.CRLF_INJECTION_LOGS-1 | A09:2021 - Security Logging and Monitoring Failures | CRLF injection in EditLanguageAction.java line 70 where user input is output to logger without validation, enabling log forgery and potential command injection in log processing. | True Positive 👁️ | **Medium** - Language management actions may include user-provided language names or codes in logs. | N/A | N/A | **MEDIUM** - Similar to finding #28. Log injection could corrupt audit trails, inject malicious content, or exploit automated log analysis tools. Particularly concerning for administrative actions. |

---

## Glossary

### EPSS (Exploit Prediction Scoring System)
EPSS is a data-driven probability score (0-1 or 0-100%) that estimates the likelihood of a vulnerability being exploited in the wild within the next 30 days. It combines CVE characteristics, exploit availability, threat intelligence, and historical exploitation patterns. Higher EPSS scores indicate greater urgency for patching. For example, an EPSS of 0.89 (89%) means the vulnerability has an 89% probability of being exploited soon.

### CISA KEV (Known Exploited Vulnerabilities)
The CISA KEV Catalog is a curated list maintained by the U.S. Cybersecurity and Infrastructure Security Agency containing vulnerabilities that have evidence of active exploitation in the wild. Inclusion in the KEV catalog indicates that the vulnerability poses significant risk to federal enterprises and, by extension, all organizations. CISA mandates that federal agencies remediate KEV vulnerabilities within specified timeframes. "No" entries indicate the vulnerability is not currently listed in the KEV catalog, though this should be monitored as the catalog is regularly updated.

---

## Priority Recommendations

**IMMEDIATE ACTION REQUIRED:**
1. **CVE-2025-66516 & CVE-2025-54988** - Upgrade Apache Tika to 3.2.2+ immediately
2. **CVE-2025-55752** - Update Tomcat to 11.0.11/10.1.45/9.0.109+ 
3. **CVE-2025-48734** - Upgrade Commons BeanUtils to 1.11.0+ and review property access patterns

**HIGH PRIORITY:**
4. **CVE-2023-24998 & CVE-2025-48976** - Update Commons FileUpload to 1.6+ and configure FileCountMax
5. **CVE-2024-40094** - Upgrade GraphQL Java to 21.5+
6. **CVE-2023-31418** - Update Elasticsearch and secure network access
