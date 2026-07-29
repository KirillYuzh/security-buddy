# Threat Modeling — Common Threats

Use these references when identifying threats:

- [OWASP Threat Model Cookbook](https://github.com/OWASP/threat-model-cookbook) — published examples for common patterns.
- [Threat Modeling Templates](https://github.com/OWASP/Threat-Modeling-Templates) — reusable templates.
- [Threat Modeling Cheat Sheets](https://github.com/OWASP/Threat-Modeling-Cheat-Sheets) — STRIDE, attack trees.
- [OWASP Cornucopia](https://owasp.org/www-project-cornucopia/) — card game for identifying threats.

## MITRE References
- [MITRE ATT&CK](https://attack.mitre.org/) maps tactics → techniques → sub-techniques. Use the [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/) to model adversary behaviors during threat modeling.
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — layer your threat model → map controls to techniques → identify coverage gaps.
- [CAPEC](https://capec.mitre.org/) provides the attack patterns. Each pattern includes: attack prerequisites, related CWEs, typical severity, and mitigation strategies.
- [CWE](https://cwe.mitre.org/) links CAPEC patterns to specific weakness classes.

**Workflow during threat modeling:**
1. Define system architecture (data flows, trust boundaries, assets).
2. Identify relevant ATT&CK techniques per asset.
3. Look up related CAPEC patterns to understand *how* the attack works.
4. Map to CWEs to understand *what* weakness enables it.
5. Apply OWASP controls (ASVS, Cheat Sheets, Top 10) as mitigations.

## Tools
- [Threat Dragon](https://github.com/OWASP/threat-dragon) — web-based threat modeling tool.
- [pytm](https://github.com/OWASP/pytm) — Pythonic threat modeling as code.
- [Threat Modeling Tools](https://github.com/OWASP/Threat-Modeling-Tools) — tool landscape survey.