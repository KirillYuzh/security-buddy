# Verification Standards

OWASP provides several standards to measure and verify application security. These are not just checklists — they are frameworks for integrating security into the entire software lifecycle.

## ASVS (Application Security Verification Standard)
[OWASP ASVS](https://github.com/OWASP/ASVS) is a framework of security requirements organized by verification level:
- **Level 1 (L1)**: Automated scanning — minimum standard for all applications.
- **Level 2 (L2)**: Manual reviews — appropriate for apps handling sensitive data.
- **Level 3 (L3)**: In-depth design verification — for high-security applications (finance, healthcare, critical infrastructure).

ASVS covers 14 categories including authentication, session management, access control, cryptography, and file uploads.

## SAMM (Software Assurance Maturity Model)
[OWASP SAMM](https://github.com/OWASP/samm) helps organizations formulate and implement a software security strategy. It maps security practices across five business functions:
- Governance
- Design
- Implementation
- Verification
- Operations

Each function has maturity levels (0–3), allowing you to set measurable security goals.

## SCVS (Software Component Verification Standard)
[OWASP SCVS](https://github.com/OWASP/Software-Component-Verification-Standard) focuses on the supply chain — identifying and reducing risk from third-party components. It covers:
- Inventory of components (SBOM)
- Automated vulnerability checks
- License compliance
- Operational risk assessment

## Software Security 5D Framework
[5D Framework](https://github.com/OWASP/Software-Security-5D-Framework) — a multi-dimensional approach covering policies, standards, procedures, guidelines, and metrics.

## Risk Assessment Framework
[OWASP Risk Assessment Framework](https://github.com/OWASP/RiskAssessmentFramework) — the Secure Coding Framework for risk-based decision making.

## Tests
- Use the [OWASP Benchmark](https://github.com/OWASP/benchmark) to evaluate your SAST/DAST tool accuracy against known vulnerabilities.
- Map your findings to ASVS categories in your reporting.
- Set SAMM targets as quarterly goals and assess progress with the SAMM toolkit.