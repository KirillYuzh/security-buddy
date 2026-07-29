# Container & Cloud Vulnerabilities

References:
- [OWASP Docker Top 10](https://owasp.org/www-project-docker-top-10/) — top container risks.
- [Container Security Verification Standard](https://github.com/OWASP/Container-Security-Verification-Standard) — security requirements.
- [Cloud-Native Application Security Top 10](https://github.com/OWASP/Cloud-Native-Application-Security-Top-10) — cloud-native risks.

| Risk | Mitigation |
| :--- | :--- |
| Vulnerable base images | Scan with Trivy/Grype in CI; use distroless |
| Privilege escalation in container | Run as non-root, drop all capabilities |
| Insecure kubeconfig/Secrets | Use External Secrets Operator, encrypt at rest |
| Wide network policies | Default-deny network policies, explicit allow |
| Serverless event injection | Validate event source, input schema, set timeouts |

See also: [OWASP Docker Security](https://github.com/OWASP/Docker-Security), [OWASP Cloud Security](https://github.com/OWASP/www-project-cloud-security)