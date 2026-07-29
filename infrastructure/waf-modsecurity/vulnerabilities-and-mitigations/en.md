# WAF & ModSecurity

## ModSecurity Core Rule Set (CRS)
[OWASP ModSecurity Core Rule Set](https://github.com/OWASP/www-project-modsecurity-core-rule-set) protects against:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI), Remote File Inclusion (RFI)
- Remote Code Execution (RCE)
- Session fixation, HTTP protocol violations

## AppSensor
[OWASP AppSensor](https://github.com/OWASP/AppSensor-Handbook) — application-level intrusion detection. Detects abuse pattern that CRS might miss (e.g., a user rapidly modifying parameters suggests automated scanning rather than a single SQLi payload).

## Secure Headers
[OWASP Secure Headers](https://github.com/OWASP/Secure-Headers) — HSTS, CSP, X-Frame-Options, etc. Complement WAF by hardening browser-side security.

## MITRE References
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) — WAF is one of the primary defenses against this technique.
- [T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) — WAF can detect and block exploit attempts against exposed services.
- [T1203 — Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/) — AppSensor detects abuse patterns before exploitation succeeds.
- [CAPEC-149: SQL Injection Through SOAP](https://capec.mitre.org/data/definitions/149.html) — CRS blocks SQLi patterns across protocols.
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html) — CRS rules for command/RCE injection detection.
