

| Number | CVE Name | CVE Type (OWASP) | Description | Status |
|--------|----------|------------------|-------------|--------|
| 1 | CVE-2016-2781 | A06:2021 - Vulnerable and Outdated Components | coreutils chroot vulnerability allowing escape via TIOCSTI ioctl - affects system-level utilities not directly used by dotCMS application code | ✗ |
| 2 | CVE-2025-0167 | A06:2021 - Vulnerable and Outdated Components | curl HTTP/2 CONTINUATION frame flood DoS - dotCMS uses HttpClient/Apache HTTP components internally, not direct curl binary execution | ✗ |
| 3 | CVE-2025-10148 | A06:2021 - Vulnerable and Outdated Components | curl OCSP response verification bypass - dotCMS Java-based HTTP clients handle certificate validation independently of curl library | ✗ |
| 4 | CVE-2025-9086 | A06:2021 - Vulnerable and Outdated Components | curl --proxy-http2 buffer over-read - dotCMS uses Java HTTP client libraries (OkHttp, Apache HttpClient) not curl for proxy operations | ✗ |
| 5 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG dirmngr denial-of-service via crafted certificate - dotCMS relies on Java cryptographic providers (JCE) and Bouncy Castle, not GnuPG/dirmngr | ✗ |
| 6 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial-of-service vulnerability - dotCMS uses Java-native cryptographic operations, not GnuPG binary tools | ✗ |
| 7 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG-utils DoS vulnerability - not utilized in dotCMS Java application runtime or core cryptographic operations | ✗ |
| 8 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GPG binary DoS vulnerability - dotCMS does not invoke GPG command-line tools for encryption/signing operations | ✗ |
| 9 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GPG-agent DoS vulnerability - dotCMS Java application does not interface with GPG agent for key management | ✗ |
| 10 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GPGconf DoS vulnerability - configuration utility not used by dotCMS application layer or cryptographic subsystems | ✗ |
