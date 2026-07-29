# Cryptography Runway

1. **Use standards, don't invent** — use NaCl/libsodium, Tink, Bouncy Castle. Never implement AES/ECC yourself.
2. **Key lifecycle** — generate keys in a secure environment (HSM/KMS), rotate regularly, revoke immediately on compromise.
3. **Defense in depth** — encrypt at rest + in transit. Assume disk/network is compromised.
4. **Cryptographic agility** — design systems so encryption algorithms can be swapped without full schema migration.
5. **Training** — use [WrongSecrets](https://github.com/OWASP/wrongsecrets) as hands-on training for developers.

Reference: [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)