# Operational Security Runway

1. **Log everything that matters** — auth, access control, data access, admin actions.
2. **Never log secrets** — sanitize logs, use structured logging for SIEM ingestion.
3. **Incident playbooks** — document runbooks for top 5 incident types (data breach, ransomware, account takeover).
4. **Regular drills** — run tabletop exercises every quarter.
5. **Virtual patching** — deploy WAF rules as temporary fixes for unpatched vulnerabilities.

Reference: [OWASP Security Logging](https://github.com/OWASP/www-project-security-logging)