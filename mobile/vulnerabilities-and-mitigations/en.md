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

## Crackmes for practice
- [Android Crackme L1](https://github.com/OWASP/owasp-mstg-crackme-a1), [L2](https://github.com/OWASP/owasp-mstg-crackme-a2), [L3](https://github.com/OWASP/owasp-mstg-crackme-a3)
- [iOS Crackme L1](https://github.com/OWASP/owasp-mstg-crackme-i1), [L2](https://github.com/OWASP/owasp-mstg-crackme-i2)