# Mobile Vulnerabilities & Mitigations

Refer to [OWASP MASVS](https://github.com/OWASP/masvs) verification levels and [MASTG](https://github.com/OWASP/mastg) test cases:

| Category | Key Weakness | Mitigation |
| :--- | :--- | :--- |
| **MASVS-STORAGE** | Insecure data storage (SQLite, SharedPrefs) | Encrypt at rest, use Android Keystore/iOS Keychain |
| **MASVS-CRYPTO** | Weak cryptography | Use platform-approved algorithms (AES-GCM, RSA-OAEP) |
| **MASVS-AUTH** | Weak local authentication | Biometric + fallback, rate limiting |
| **MASVS-NETWORK** | Cleartext traffic | Enforce TLS, implement certificate pinning |
| **MASVS-PLATFORM** | WebView XSS, IPC leaks | Disable JavaScript unless needed, validate intents |
| **MASVS-RESILIENCE** | Reverse engineering | Obfuscation, root/jailbreak detection, integrity checks |

## MITRE References
- [T1474 — DNS](https://attack.mitre.org/techniques/T1474/) — mobile-specific DNS technique for credential interception.
- [T1529 — Obtain Access to Device Data](https://attack.mitre.org/techniques/T1529/) — physical or logical access to mobile device data (maps to MASVS-STORAGE).
- [T1630 — Exploit Operating System Vulnerability](https://attack.mitre.org/techniques/T1630/) — OS-level privilege escalation on mobile (maps to MASVS-PLATFORM).
- [CAPEC-560: Mobile App Analysis](https://capec.mitre.org/data/definitions/560.html) — reverse engineering of mobile applications.
- [CAPEC-641: Mobile App Tampering](https://capec.mitre.org/data/definitions/641.html) — runtime manipulation of mobile apps.

## Crackmes for practice
- [Android Crackme L1](https://github.com/OWASP/owasp-mstg-crackme-a1), [L2](https://github.com/OWASP/owasp-mstg-crackme-a2), [L3](https://github.com/OWASP/owasp-mstg-crackme-a3)
- [iOS Crackme L1](https://github.com/OWASP/owasp-mstg-crackme-i1), [L2](https://github.com/OWASP/owasp-mstg-crackme-i2)