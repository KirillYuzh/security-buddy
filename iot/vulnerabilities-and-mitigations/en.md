# IoT Vulnerabilities & Mitigations

[OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things-top-10/):

| Risk | Mitigation |
| :--- | :--- |
| I1: Weak/Hardcoded Passwords | Enforce password complexity, unique device credentials |
| I2: Insecure Network Services | Disable unused ports/services, use encrypted protocols |
| I3: Insecure Ecosystem Interfaces | Harden web/mobile/cloud backends |
| I4: Lack of Secure Update | Sign updates, enforce version rollback protection |
| I5: Outdated Components | Track firmware dependencies, scan for CVEs |
| I6: Privacy | Minimize data collection, encrypt at rest |
| I7: Insecure Data Transfer | Enforce TLS on all external communication |
| I8: Lack of Device Management | Implement remote deactivation, logging |
| I9: Insecure Default Settings | Security-hardened defaults out of box |
| I10: Physical Hardening | Disable debug ports, tamper-resistant casing |

## MITRE References
- [T0813 — Exploit Automation of Device](https://attack.mitre.org/techniques/T0813/) — automated exploitation of IoT device vulnerabilities.
- [T0821 — Device Reset](https://attack.mitre.org/techniques/T0821/) — remote device wipe or reset without authorization.
- [T0844 — Block Command Message](https://attack.mitre.org/techniques/T0844/) — blocking firmware update commands (maps to I4: Lack of Secure Update).
- [CAPEC-560: Hardware Analysis](https://capec.mitre.org/data/definitions/560.html) — physical attack patterns for embedded/IoT devices.
- [CAPEC-457: USB Memory Attack](https://capec.mitre.org/data/definitions/457.html) — physical USB attack vector for IoT devices.

See also: [OWASP Embedded Application Security](https://owasp.org/www-project-embedded-application-security/)
