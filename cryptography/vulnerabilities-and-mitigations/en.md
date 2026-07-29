# Cryptography Vulnerabilities & Mitigations

## Common Crypto Weaknesses

| Weakness | CWE | Mitigation |
| :--- | :--- | :--- |
| Weak hash for passwords | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use Argon2id, bcrypt, scrypt |
| Hardcoded cryptographic keys | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use KMS/Vault, never hardcode |
| Insufficient key size | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | AES-256, RSA-3072+, ECC P-256 |
| Use of broken or risky algorithm | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Replace MD5, SHA-1, DES, RC4 with modern alternatives |
| Improper certificate validation | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Pin certificates, validate full chain |
| Missing encryption of sensitive data | [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Encrypt at rest and in transit |
| Predictable IV/nonce | [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Use random nonces, ensure AES-GCM nonce uniqueness |
| Cleartext storage of sensitive data | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Encrypt storage, use platform keystores |

## OWASP Resources
- [OWASP WrongSecrets](https://github.com/OWASP/wrongsecrets) — deliberately vulnerable app showing how *not* to handle secrets. Interactive training for crypto, secrets management, and hardcoded credentials.
- [WrongSecrets CTF Party](https://github.com/OWASP/wrongsecrets-ctf-party) — CTF companion for WrongSecrets.
- [OWASP O-Saft](https://github.com/OWASP/O-Saft) — TLS/SSL assessment tool. Test cipher strength, certificate validity, protocol versions.
- [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [OWASP Cheat Sheet: TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Tools
- `openssl speed` / `openssl s_client` — quick TLS checks
- `testssl.sh` — full TLS/SSL assessment
- `truffleHog`, `gitleaks` — scan for hardcoded keys
- `cosign` — sign and verify container images

## MITRE References
- [T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) — attacker technique for finding secrets in files, repos, env vars
- [T1525 — Implant Container Image](https://attack.mitre.org/techniques/T1525/) — supply chain via unsigned images
- [CAPEC-536: Data Interception](https://capec.mitre.org/data/definitions/536.html) — intercepting unencrypted communications