# Security Buddy

SKILLS, tests and approaches to developing secure applications.

# Structure

This repository is divided into folders based on their specific features:

- [general](./general/) — core skills, vulnerabilities, testing approaches
- [ai-based](./ai-based/) — application security for LLMs and ML systems
- [api](./api/) — API security (Top 10, testing, schema validation)
- [mobile](./mobile/) — mobile application security (MASVS, MASTG, MobSF)
- [iot](./iot/) — IoT & embedded security (IoT Top 10, firmware analysis)
- [supply-chain](./supply-chain/) — software supply chain security (SCVS, SBOM, Dependency-Track)
- [threat-modeling](./threat-modeling/) — threat modeling tools and techniques
- [tools](./tools/) — OWASP tools ecosystem (ZAP, Amass, Dependency-Check, etc.)
- [infrastructure](./infrastructure/) — infrastructure-level topics
    - [container-cloud-security](./infrastructure/container-cloud-security/) — Docker, Kubernetes, serverless
    - [devsecops](./infrastructure/devsecops/) — CI/CD security, pipeline hardening
    - [waf-modsecurity](./infrastructure/waf-modsecurity/) — ModSecurity CRS, AppSensor, Secure Headers
    - [operational-security](./infrastructure/operational-security/) — logging, incident response, ransomware defense
    - [general](./infrastructure/general/) — infrastructure general
    - [microservises](./infrastructure/microservises/) — microservices security
    - [ansible](./infrastructure/ansible/) — Ansible security
- [cryptography](./cryptography/) — cryptographic practices (WrongSecrets, O-Saft, key management, cipher choices)

Each folder consists of several standard parts:
- **general** — overview entry point for the topic
- **SKILLS** — core competencies and techniques
- **vulnerabilities-and-mitigations** — known risks and countermeasures
- **runway** — thinking approach, architecture, HITL methodology
- **tests** (optional) — test types and tooling references
    - A single `en.md` or subdivided into SAST / SCA / DAST

> [!NOTE]
> All the specific domains (everything but `general` folder) are based on approaches and practices described in `general`.

> [!NOTE]
> Folder `tests` won't always contain ready set of tests. It must be used for reference only.

# Sources

You can explore sources used in this repo in [sources](./sources.md) document.

# Issues

Any improvements and found issues can be added to the appropriate section of this repo.

🏄🏻 **I will always be happy for your feedback!** 🏄🏻