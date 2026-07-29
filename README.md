# Security Buddy

SKILLS, tests and approaches to developing secure applications.

This repository is designed as a **knowledge base for AI agents and developers**. Every domain folder follows the same structure so that an AI can autonomously navigate and find relevant security guidance.

## Navigation Pattern (for AI agents)

To answer a security question, follow this algorithm:

```
1. Identify the domain(s) relevant to the question
2. Read <domain>/general/en.md        → overview + context
3. Read <domain>/SKILLS/en.md         → actionable techniques
4. Read <domain>/vulnerabilities-and-mitigations/en.md → risks + countermeasures
5. Read <domain>/tests/en.md          → test strategies
6. Read <domain>/runway/en.md         → methodology + integration approach
7. Use sources.md for official references
```

> [!TIP]
> See [AGENT.md](./AGENT.md) for a copy-paste prompt that makes any AI model follow this pattern autonomously.
> See [prompts/](./prompts/) for specialized prompts (secure code review, LLM-as-a-Judge, Security Expert Agent for multi-agent systems).

# Structure

## Domains

| Domain | Description | Key OWASP references |
|--------|-------------|---------------------|
| [general/](./general/) | Core skills, vulnerabilities, testing methodology | Top 10, ASVS, WSTG, Secure Coding Practices |
| [api/](./api/) | API security | API Security Top 10, REST/GraphQL cheat sheets |
| [mobile/](./mobile/) | Mobile application security | MASVS, MASTG, Mobile Top 10, MobSF |
| [iot/](./iot/) | IoT & embedded security | IoT Top 10, Embedded Application Security |
| [supply-chain/](./supply-chain/) | Software supply chain security | SCVS, SBOM/CycloneDX, Dependency-Track |
| [threat-modeling/](./threat-modeling/) | Threat modeling | Threat Dragon, pytm, Cornucopia, STRIDE |
| [tools/](./tools/) | OWASP tools ecosystem | ZAP, Amass, Dependency-Check, Encoders/Sanitizers |
| [cryptography/](./cryptography/) | Cryptographic practices | WrongSecrets, O-Saft, Cryptographic Storage Cheat Sheet |
| [infrastructure/](./infrastructure/) | Infrastructure-level topics | — |

### Infrastructure sub-domains

| Sub-domain | Description |
|------------|-------------|
| [container-cloud-security/](./infrastructure/container-cloud-security/) | Docker Top 10, CSVS, Cloud-Native Top 10, k8s security |
| [devsecops/](./infrastructure/devsecops/) | DSOMM, DefectDojo, SecureCodeBox, pipeline hardening |
| [waf-modsecurity/](./infrastructure/waf-modsecurity/) | ModSecurity CRS, AppSensor, Secure Headers |
| [operational-security/](./infrastructure/operational-security/) | Security Logging, Incident Response, Anti-Ransomware |
| [general/](./infrastructure/general/) | Infrastructure general |
| [microservises/](./infrastructure/microservises/) | Microservices security |
| [ansible/](./infrastructure/ansible/) | Ansible security |

## Standard folder structure (every domain)

```
<domain>/
├── general/                   # Overview entry point for the topic
│   └── en.md
├── SKILLS/                    # Core competencies and techniques
│   └── en.md
├── vulnerabilities-and-mitigations/  # Known risks and countermeasures
│   └── en.md
├── runway/                    # Methodology, architecture, HITL
│   └── en.md
└── tests/                     # Test types and tooling (optional)
    ├── en.md
    ├── sast/en.md             # Static analysis tests
    ├── sca/en.md              # Software composition tests
    └── dast/en.md             # Dynamic analysis tests
```

> [!NOTE]
> All domain-specific folders rely on the cross-cutting foundations in [general/](./general/).
> Tests folders are reference material and may not contain ready-to-run test suites.

# Sources

You can explore sources used in this repo in [sources](./sources.md) document.

# Issues

Any improvements and found issues can be added to the appropriate section of this repo.

🏄🏻 **I will always be happy for your feedback!** 🏄🏻