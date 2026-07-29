# Vulnerabilities & Mitigations

Firstly, make sure that you understand all common vulnerabilities - read [OWASP Top 10](https://owasp.org/Top10/2025/).

## CVE, CWE

**CVE** (Common Vulnerabilities and Exposures) is a dictionary of publicly disclosed cybersecurity vulnerabilities. Each CVE entry has a unique identifier in the format `CVE-YYYY-NNNNN`. Think of it as a specific "incident report" for a known flaw. You can search CVEs at [cve.mitre.org](https://cve.mitre.org/) or via the [NVD (National Vulnerability Database)](https://nvd.nist.gov/).

**CWE** (Common Weakness Enumeration) is a taxonomy of common software and hardware weakness types. Each CWE entry has a unique identifier like `CWE-79` (Cross-Site Scripting). Think of it as a "category" or "class" of vulnerability. OWASP Top 10 entries map directly to CWEs. Explore the full list at [cwe.mitre.org](https://cwe.mitre.org/).

The relationship is simple: a **CWE** is the *type* of weakness, and a **CVE** is a *specific instance* of that weakness found in a real product. For example, `CVE-2023-44487` (HTTP/2 Rapid Reset attack) is an instance of the weakness class `CWE-770` (Allocation of Resources Without Limits or Throttling).

When assessing a finding in your reports:
1. Identify the **CWE** class (gives you the category of the issue).
2. Locate the matching **CVE** if one exists (tells you if there's a known exploit in the wild).
3. Use OWASP references to understand the mitigation.

Useful references:
- [OWASP CWE page](https://owasp.org/www-community/OWASP_CWE_Matrix)
- [NVD Search](https://nvd.nist.gov/)
- [CVE.org](https://www.cve.org/)

## MITRE ATT&CK

[MITRE ATT&CK](https://attack.mitre.org/) is a globally-accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. It helps security teams think like attackers and model their defenses accordingly.

### Structure

ATT&CK is organized as **Tactics → Techniques → Sub-Techniques**:

- **Tactics** (the "why") — the adversary's objective, e.g. [Initial Access](https://attack.mitre.org/tactics/TA0001/), [Execution](https://attack.mitre.org/tactics/TA0002/), [Persistence](https://attack.mitre.org/tactics/TA0003/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/), [Defense Evasion](https://attack.mitre.org/tactics/TA0005/), [Credential Access](https://attack.mitre.org/tactics/TA0006/), [Discovery](https://attack.mitre.org/tactics/TA0007/), [Lateral Movement](https://attack.mitre.org/tactics/TA0008/), [Collection](https://attack.mitre.org/tactics/TA0009/), [Command and Control](https://attack.mitre.org/tactics/TA0011/), [Exfiltration](https://attack.mitre.org/tactics/TA0010/), [Impact](https://attack.mitre.org/tactics/TA0040/)
- **Techniques** (the "what") — specific methods used to achieve a tactic, e.g. [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **Sub-Techniques** (the "how") — more granular detail, e.g. [T1078.003 — Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

### Matrices

- [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/) — Windows, macOS, Linux, Cloud (IaaS/SaaS), Containers, Network Devices
- [Mobile Matrix](https://attack.mitre.org/matrices/mobile/) — iOS and Android threat landscape
- [ICS Matrix](https://attack.mitre.org/matrices/ics/) — Industrial Control Systems

### ATT&CK in AppSec

Each ATT&CK technique maps to CWEs and OWASP controls. For example:
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) → use OWASP Top 10 & ASVS for web app hardening
- [T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) → apply WAF + AppSensor
- [T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) → use WrongSecrets principles, secret scanning

Use ATT&CK to:
1. Model the threats your application faces (threat intelligence-driven).
2. Map existing security controls to specific techniques.
3. Identify gaps — which techniques have no controls?
4. Communicate risks in a language that both technical and non-technical teams understand.

References:
- [ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — visualize and analyze coverage
- [ATT&CK in OWASP](https://owasp.org/www-project-cyber-defense-matrix/) — OWASP × MITRE mapping

## CAPEC

**CAPEC** (Common Attack Pattern Enumeration and Classification) by MITRE is a comprehensive dictionary of known attack patterns used by adversaries to exploit weaknesses. Each CAPEC ID (e.g. `CAPEC-242` — Code Injection) describes the attack mechanism, prerequisites, related weaknesses (CWEs), and mitigations.

CAPEC helps you:
- Understand *how* an attacker might exploit a given weakness
- Design test cases based on real attack patterns
- Link threats (CAPEC) → weaknesses (CWE) → controls (OWASP)

For example:
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html) → CWE-94 → OWASP ASVS V5 (Input Validation)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html) → CWE-89 → OWASP ASVS V5

Explore CAPEC at [capec.mitre.org](https://capec.mitre.org/).

## MITRE × OWASP × CWE Workflow

When building security requirements or reviewing a system:

1. **CAPEC** — identify the attack pattern (the "how").
2. **CWE** — identify the underlying weakness class (the "what").
3. **CVE** — check for real-world instances of that weakness.
4. **ATT&CK** — understand the tactic and technique in context.
5. **OWASP** — implement the control (Top 10, ASVS, Cheat Sheets).