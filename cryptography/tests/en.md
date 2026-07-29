# Cryptography Tests

| Check | Tool/Method |
| :--- | :--- |
| Weak cipher detection | `testssl.sh`, `O-Saft` |
| Hardcoded keys/secrets | `truffleHog`, `gitleaks`, `git-secrets` |
| WrongSecrets CTF | Deploy WrongSecrets, solve challenges, identify fix patterns |
| TLS configuration | `testssl.sh --rating`, `SSL Labs API` |
| Password hashing audit | Inspect `Argon2id`/`bcrypt`/`scrypt` usage in code |
| Key rotation drill | Rotate KMS keys, verify old keys are disabled |
| Cryptographic agility test | Simulate algorithm deprecation, verify upgrade path |