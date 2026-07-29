# Supply Chain Vulnerabilities & Mitigations

The [OWASP SCVS](https://github.com/OWASP/Software-Component-Verification-Standard) framework covers:

| Risk | Mitigation |
| :--- | :--- |
| Known vulnerable dependencies | Use OWASP Dependency-Check / Dependency-Track |
| Malicious packages | Package lockfile integrity checks, signed commits |
| Outdated components | SBOM-driven freshness monitoring |
| License violations | Automated license scanning in CI |
| Build pipeline compromise | Provenance attestation, reproducible builds |

## Tools
- [Dependency-Check](https://github.com/OWASP/dependency-check) — SCA for known vulnerabilities.
- [Dependency-Track](https://github.com/OWASP/dependency-track) — continuous component analysis platform.
- [OWASP CycloneDX](https://cyclonedx.org/) — SBOM standard.
- [OWASP Software Composition Security](https://github.com/OWASP/Software-Composition-Security) — overall guidance.

For ML pipelines, also monitor model weights and LoRA adapter provenance (see [LLM03: Supply Chain](https://owasp.org/www-project-top-10-for-large-language-model-applications/)).