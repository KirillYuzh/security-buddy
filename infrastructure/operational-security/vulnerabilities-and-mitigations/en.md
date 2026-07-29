# Operational Security Vulnerabilities & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| Insufficient logging | Log all auth/access control failures; ship to SIEM |
| Logging secrets/PII | Sanitize logs at source; use structured logging |
| No incident response plan | Use [OWASP Incident Response](https://github.com/OWASP/www-project-incident-response) playbooks |
| Ransomware | 3-2-1 backup, test restoration drills, [Anti-Ransomware Guide](https://github.com/OWASP/www-project-anti-ransomware-guide) |
| Unpatched production vulns | Virtual patching via [OWASP Virtual Patching Guide](https://owasp.org/www-project-virtual-patching-best-practices/) |
| No application-level IDS | Deploy [AppSensor](https://github.com/OWASP/AppSensor-Handbook) detection points |

References:
- [OWASP Security Logging](https://github.com/OWASP/www-project-security-logging)
- [OWASP Virtual Patching Best Practices](https://owasp.org/www-project-virtual-patching-best-practices/)