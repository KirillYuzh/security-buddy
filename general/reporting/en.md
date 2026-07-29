# AppSec Reporting

A security report is not just a list of vulnerabilities — it is a **strategic document** that translates technical risk into business language, gives clear instructions to developers, and serves as a foundation for continuous security improvement. It must be understandable to both a CISO and a developer.

## Report Structure

### 1. Introduction

| Section | Description |
|---------|-------------|
| **Version Control** | Document change history table |
| **The Team** | List of assessors with roles and competencies |
| **Scope** | What was tested (apps, APIs, microservices, environments) and what was out of scope |
| **Limitations** | Factors that may have affected coverage (time, no code access, broken functionality) |
| **Disclaimer** | Report reflects state at time of testing, not a guarantee of no vulnerabilities |

### 2. Executive Summary

This section is the "elevator pitch" for management.

- **Brief overview**: testing objectives and business value
- **Overall security posture**: score (e.g., "9.2/10", lower is better)
- **Key risks in business context**: not "SQL injection" but "customer data leak → GDPR fines + reputation loss"
- **Overall statistics**: visualization of findings by severity (Critical, High, Medium, Low)
- **Strategic recommendations**: non-technical advice (e.g., "implement secure coding training", "integrate SAST into CI/CD")

### 3. Methodology

A clear description of **how** the assessment was conducted.

- **Standards & frameworks used**: OWASP Top 10, OWASP ASVS, MITRE ATT&CK (mapping to tactics and techniques)
- **Tools & techniques**: SAST, DAST, SCA, architecture analysis, threat modeling, manual code review

### 4. Detailed Findings

The technical core of the report. Each finding must follow this structure:

| Field | Description |
|-------|-------------|
| **Title** | Clear, positive action (e.g., "Implement parameterized queries to prevent SQL injection" not "SQL injection in login module") |
| **Unique ID** | e.g., `PST-2024-017` |
| **Location** | Exact location (file:lines, URL, API endpoint, component) |
| **Description** | Clear explanation of the vulnerability |
| **Technical Impact** | What an attacker can do, with proof (code snippets, logs, screenshots). Include the **attack chain** mapped to MITRE ATT&CK tactics |
| **Business Impact** | Business consequences (financial loss, reputation damage, legal liability) |
| **Risk Rating** | Severity (Critical, High, Medium, Low) with **justification**. Use OWASP Risk Rating Methodology or CVSS |
| **Remediation** | Step-by-step instructions with "before" and "after" code examples. Include estimated effort |
| **References** | External sources (CWE, CVE, OWASP Top 10, MITRE ATT&CK) |

### 5. Remediation Roadmap

Tasks grouped by urgency for resource planning:

- **Fix Immediately** (0-24 hours)
- **High Priority** (within 1 week)
- **Medium Priority** (within 1 month)
- **Low Priority** (next release)
- **Security control implementation plan**: tooling and process improvement proposals

### 6. Appendices

- Technical details that would overload the main report (full code listings, raw logs, config dumps)
- **Compliance Checklist**: mapping to standards (OWASP ASVS, PCI DSS, GDPR)
- **Attestation Letter**: official confirmation of the assessment

## Tips for Good Findings

- **Name findings as positive actions** — "Implement multi-factor authentication" is better than "Missing MFA"
- **Always include before/after code** — developers need to see exactly what to change
- **Map to ATT&CK** — show the attack chain to demonstrate real-world impact
- **Justify severity** — don't just assign a score, explain why
- **Reference CWE/CVE** — provides external authority and helps tooling

## Standards & Regulations for Security Reporting

There are both national and international standards that govern how application security reports should be structured and what they must contain. Understanding these helps you align your report with formal audit requirements, legal frameworks, and industry best practices.

### Russian National Standards (ГОСТ)

Two key national standards, developed by Technical Committee TC 362 "Information Protection", define vulnerability description rules and secure development processes:

1. **ГОСТ Р 56545-2015 "Information Protection. Vulnerabilities of Information Systems. Rules for Vulnerability Description"**
   - **What it is:** Directly establishes the **rules for describing vulnerabilities** and defines the structure of a document called the **"Vulnerability Passport"**.
   - **Passport contents:** Each vulnerability record must include: identifier, name, vulnerability class, software version, location, discovery method, and remediation measures. This is the formal skeleton for every finding in your report — similar to how OWASP defines finding fields, but at a regulatory level.
   - **Source:** Available via Rosstandart and National Standards databases.

2. **ГОСТ Р 56939-2016 "Information Protection. Secure Software Development. General Requirements"**
   - **What it is:** Describes the **process of secure software development**. It provides context for your report by defining what security measures should be embedded in design, implementation, and testing processes. Referencing this ГОСТ helps justify *why* a vulnerability exists — often because a secure development process was not followed.
   - **Source:** Available via Rosstandart and National Standards databases.

> **Usage tip:** Structure each finding to align with the Vulnerability Passport format from ГОСТ Р 56545-2015. When a finding reveals a process gap (e.g., no security review before release), reference ГОСТ Р 56939-2016 as the standard that was violated.

### International Standards and Frameworks

International standards typically define *what a secure system should look like* rather than prescribing a specific report template. Your report serves as evidence that these requirements have (or have not) been met.

1. **NIST SP 800-53 (USA)**
   - **What it is:** Under NIST SP 800-53, the **Security Assessment Report (SAR)** is a mandatory deliverable. It must summarize control test results, clearly identify weaknesses, and include a **Plan of Action and Milestones (POA&M)** — a remediation plan with deadlines and assignees.
   - **Relevance to your report:** The POA&M concept maps directly to your Remediation Roadmap section. Each finding should be traceable to a specific NIST control family (e.g., SI-10 for input validation, SC-13 for cryptography).
   - **Source:** [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

2. **ISO/IEC 27001**
   - **What it is:** The international standard for Information Security Management Systems (ISMS). It requires documenting risk assessment results and control selection. While it doesn't prescribe a specific report format, professional security reports should map findings to the control objectives in **Annex A.14** (Security in development and support processes).
   - **Relevance to your report:** Annex A.14 covers secure development, change management, and testing. Aligning your findings with these controls makes the report directly useful for ISO 27001 auditors and certification processes.
   - **Source:** [ISO/IEC 27001](https://www.iso.org/standard/27001)

3. **OWASP (Open Web Application Security Project)**
   - **What it is:** The de facto global standard for application security. OWASP provides both the **OWASP Risk Rating Methodology** for assigning severity and a community-accepted approach to describing vulnerabilities. Commercial and open-source tools (e.g., Dradis, DefectDojo) often ship with built-in OWASP-style report templates.
   - **Relevance to your report:** Use OWASP finding structure as your default. Map each finding to OWASP Top 10 categories and ASVS verification levels. This creates a report that every AppSec professional can immediately understand.
   - **Source:** [OWASP Reporting](https://owasp.org/www-project-application-security-verification-standard/)

### Cross-Reference: Finding Field Alignment

| Your Finding Field | ГОСТ R 56545-2015 | NIST SP 800-53 SAR | OWASP / ISO 27001 |
|--------------------|-------------------|---------------------|---------------------|
| Unique ID | Identifier | Finding ID | CVE / OWASP ID |
| Title | Name | Control name | Weakness name |
| Location | Place of occurrence | Affected system | Component |
| Description | Vulnerability description | Finding detail | Description |
| Technical Impact | Consequence | Impact analysis | Impact |
| Business Impact | — | Risk exposure | Risk assessment |
| Risk Rating | Criticality class | Severity (low/mod/high/crit) | CVSS / OWASP Risk Rating |
| Remediation | Remediation measures | POA&M entry | Recommendation |
| References | CWE/CVE links | Related controls | CWE, CVE, OWASP Top 10 |

### Key Takeaway

**International standards (NIST, ISO/IEC 27001, OWASP) define the approach and requirements for a security report. Russian ГОСТ standards (R 56545-2015, R 56939-2016) provide a formalized structure and terminology for describing vulnerabilities at the state level. An ideal report synthesizes best practices from all these sources — using OWASP as the accessible baseline, ГОСТ for regulatory compliance, and NIST/ISO for auditor alignment.**

## References

- [OWASP Code Review Finding Template](https://wiki.owasp.org/index.php/How_to_Write_an_Application_Code_Review_Finding) — classic single-finding structure
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) — calculate severity from impact and likelihood
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1) — industry-standard scoring
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — visualize attack chain coverage
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — requirements framework
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — security and privacy controls, SAR guidance
- [ISO/IEC 27001](https://www.iso.org/standard/27001) — information security management standard
- [ГОСТ Р 56545-2015](https://docs.cntd.ru/document/1200123701) — rules for vulnerability description (Russian)
- [ГОСТ Р 56939-2016](https://docs.cntd.ru/document/1200135525) — secure software development requirements (Russian)
