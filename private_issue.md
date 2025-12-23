`private-issues`

A private repo to store Github issues that might need to contain non-public info so that they don't become public by way of default in dotcms/core.

`Github Project`

We purposely decided not to create a separate github project for these issues because it’s hard to keep everything in sync. At time of writing, our desired approach is to use a private repo for issues that have some sensitivity on them and to assign those issues to our standard [dotCMS - Product Planning](url project. Although the dotCMS - project Planning project is public, issues that belong to a private repo remain invisible to those without permissions.

`Labels`

Labels will be tricky. They are one of the things that we need to manually keep in sync. For the initial import of labels to this repo, I used the github CLI.

``gh label clone dotcms/core -R dotcms/cloud-engineering-issues``


## Automated Security Analysis Table
Generated on: Mon Dec 22 05:48:32 UTC 2025


| Number | CVE Name | CVE Type (OWASP) | Description | Status |
|--------|----------|------------------|-------------|--------|
| 1 | CVE-2016-2781 | A09:2021 - Security Logging and Monitoring Failures | chroot in GNU coreutils allows local users to escape to the parent directory via a crafted TIOCSTI ioctl call. This is a system-level vulnerability in the coreutils package affecting the chroot command's ability to maintain directory confinement. | ✗ |
| 2 | CVE-2025-0167 | A05:2021 - Security Misconfiguration | curl OCSP stapling bypass vulnerability where CURLOPT_SSL_VERIFYSTATUS is ignored in certain conditions. Affects libcurl's ability to properly verify OCSP responses during TLS connections. | ✗ |
| 3 | CVE-2025-10148 | A07:2021 - Identification and Authentication Failures | curl vulnerability in the OCSP verification where intermediate certificates could fail verification. Affects TLS certificate validation when using OCSP stapling. | ✗ |
| 4 | CVE-2025-9086 | A03:2021 - Injection | curl RTSP handling vulnerability that could allow attackers to inject CRLF sequences into RTSP headers leading to header injection attacks. | ✗ |
| 5 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |
| 6 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |
| 7 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |
| 8 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |
| 9 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |
| 10 | CVE-2022-3219 | A02:2021 - Cryptographic Failures | GnuPG denial of service vulnerability due to malformed input in clearsigned documents. An attacker can cause gpgv to hang indefinitely by providing specially crafted input. | ✗ |


## Automated Security Analysis Table
Generated on: Tue Dec 23 03:20:00 UTC 2025


| Number | CVE Name | CVE Type (OWASP) | Description | Status |
|--------|----------|------------------|-------------|--------|
| 1 | CVE-2016-2781 | A09:2021 – Security Logging and Monitoring Failures | chroot in GNU coreutils allows local users to escape to the parent directory via the TIOCSTI ioctl to push characters to the terminal's input buffer. This is a system-level vulnerability in the coreutils package affecting the chroot command when run_init is not used. | ✗ |
| 2 | CVE-2025-0167 | A05:2021 – Security Misconfiguration | curl's IPFS gateway feature has a flaw in URL parsing that could allow malicious redirects. The vulnerability affects libcurl when using IPFS gateway URLs with specific crafted input. | ✗ |
| 3 | CVE-2025-10148 | A03:2021 – Injection | curl vulnerability related to SSH host key verification bypass through improper handling of SSH fingerprints, potentially allowing MITM attacks when using SSH/SCP protocols. | ✗ |
| 4 | CVE-2025-9086 | A02:2021 – Cryptographic Failures | curl vulnerability involving improper certificate validation in specific scenarios with TLS connections, potentially allowing unauthorized access through certificate spoofing. | ✗ |
| 5 | CVE-2022-3219 | A06:2021 – Vulnerable and Outdated Components | GnuPG/dirmngr denial of service vulnerability caused by resource exhaustion when processing specially crafted certificates or keyserver responses. | ✗ |
| 6 | CVE-2025-6297 | A04:2021 – Insecure Design | dpkg vulnerability related to improper privilege handling during package installation/removal operations, potentially allowing local privilege escalation. | ✗ |
| 7 | CVE-2022-3219 | A06:2021 – Vulnerable and Outdated Components | GnuPG denial of service vulnerability affecting the gnupg package through resource exhaustion in certificate processing. | ✗ |
| 8 | CVE-2022-3219 | A06:2021 – Vulnerable and Outdated Components | GnuPG denial of service vulnerability affecting gnupg-utils through resource exhaustion in certificate processing. | ✗ |
| 9 | CVE-2022-3219 | A06:2021 – Vulnerable and Outdated Components | GnuPG denial of service vulnerability affecting the gpg binary through resource exhaustion in certificate processing. | ✗ |
| 10 | CVE-2022-3219 | A06:2021 – Vulnerable and Outdated Components | GnuPG denial of service vulnerability affecting gpg-agent through resource exhaustion in certificate processing. | ✗ |
