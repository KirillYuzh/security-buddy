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