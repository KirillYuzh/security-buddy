# Supply Chain Vulnerabilities & Mitigations

The [OWASP SCVS](https://github.com/OWASP/Software-Component-Verification-Standard) framework covers:

| Risk | Mitigation |
| :--- | :--- |
| Known vulnerable dependencies | Use OWASP Dependency-Check / Dependency-Track |
| Malicious packages | Package lockfile integrity checks, signed commits |
| Outdated components | SBOM-driven freshness monitoring |
| License violations | Automated license scanning in CI |
| Build pipeline compromise | Provenance attestation, reproducible builds |

## MITRE References
- [T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) — attacker technique targeting development pipelines, CI/CD systems, and third-party dependencies.
- [T1525 — Implant Container Image](https://attack.mitre.org/techniques/T1525/) — compromise via tampered container images.
- [T1554 — Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/) — trojanized updates and dependencies.
- [CAPEC-437: Supply Chain Attack](https://capec.mitre.org/data/definitions/437.html) — attack pattern for inserting malicious components.

## Tools
- [Dependency-Check](https://github.com/OWASP/dependency-check) — SCA for known vulnerabilities.
- [Dependency-Track](https://github.com/OWASP/dependency-track) — continuous component analysis platform.
- [OWASP CycloneDX](https://cyclonedx.org/) — SBOM standard.
- [OWASP Software Composition Security](https://github.com/OWASP/Software-Composition-Security) — overall guidance.

For ML pipelines, also monitor model weights and LoRA adapter provenance (see [LLM03: Supply Chain](https://owasp.org/www-project-top-10-for-large-language-model-applications/)).