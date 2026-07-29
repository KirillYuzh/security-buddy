# DevSecOps Vulnerabilities & Mitigations

References:
- [DevSecOps Maturity Model (DSOMM)](https://github.com/OWASP/www-project-devsecops-maturity-model)
- [OWASP DefectDojo](https://github.com/OWASP/defectdojo)
- [OWASP SecureCodeBox](https://github.com/OWASP/secureCodeBox)
- [OWASP AppSec Pipeline](https://github.com/OWASP/www-project-appsec-pipeline)

| Risk | Mitigation |
| :--- | :--- |
| Leaked CI/CD secrets | Use vault-backed secrets (GitHub Actions secrets, Vault) |
| Unverified pipeline artifacts | Sign all artifacts with cosign; verify before deploy |
| Scan tool drift | Pin scanner versions; validate results with DefectDojo |
| No security gates | Define pass/fail criteria per scanning tool |
| Drift in infrastructure config | Policy-as-code checks in CI (Conftest, OPA) |

See also: [OWASP Bug Logging Tool (BLT)](https://github.com/OWASP/www-project-bug-logging-tool), [OWASP Findings Format (OFF)](https://github.com/OWASP/off)