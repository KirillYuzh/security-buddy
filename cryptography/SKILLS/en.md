# Cryptography Skills

- **Symmetric Encryption** — AES-GCM (preferred), AES-CBC + HMAC, ChaCha20-Poly1305.
- **Asymmetric Encryption** — RSA-OAEP (encryption), ECDSA/Ed25519 (signatures).
- **Hashing** — SHA-256/384/512; use for integrity, not for password storage.
- **Password Storage** — Argon2id (preferred), bcrypt/scrypt (acceptable), never SHA-1/256 alone.
- **Key Management** — use HSM or key management service (AWS KMS, Azure Key Vault, Vault).
- **TLS Configuration** — TLS 1.3 only, disable weak ciphers, pin certificates for mobile.
- **Cryptographic Agility** — design systems to rotate algorithms easily without data migration.

Always use high-level libraries (Tink, NaCl/libsodium, Bouncy Castle) and never implement crypto primitives from scratch.