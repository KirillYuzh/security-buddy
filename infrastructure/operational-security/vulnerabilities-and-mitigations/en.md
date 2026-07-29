# Operational Security Vulnerabilities & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| Insufficient logging | Log all auth/access control failures; ship to SIEM |
| Logging secrets/PII | Sanitize logs at source; use structured logging |
| No incident response plan | Use [OWASP Incident Response](https://github.com/OWASP/www-project-incident-response) playbooks |
| Ransomware | 3-2-1 backup, test restoration drills, [Anti-Ransomware Guide](https://github.com/OWASP/www-project-anti-ransomware-guide) |
| Unpatched production vulns | Virtual patching via [OWASP Virtual Patching Guide](https://owasp.org/www-project-virtual-patching-best-practices/) |
| No application-level IDS | Deploy [AppSensor](https://github.com/OWASP/AppSensor-Handbook) detection points |

## MITRE References
- [T1562 — Impair Defenses](https://attack.mitre.org/techniques/T1562/) — attackers disabling logging/IDS/endpoint detection (maps to insufficient logging).
- [T1070 — Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/) — clearing logs to avoid detection.
- [T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/) — ransomware impact; maps to Anti-Ransomware Guide.
- [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) — accessing unsecured cloud buckets; requires monitoring.
- [CAPEC-484: Data Exfiltration](https://capec.mitre.org/data/definitions/484.html) — attack pattern for extracting data; requires logging and detection.

References:
- [OWASP Security Logging](https://github.com/OWASP/www-project-security-logging)
- [OWASP Virtual Patching Best Practices](https://owasp.org/www-project-virtual-patching-best-practices/)
