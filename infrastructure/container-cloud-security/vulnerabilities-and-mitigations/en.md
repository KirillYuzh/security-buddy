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

## MITRE References
- [T1610 — Deploy Container](https://attack.mitre.org/techniques/T1610/) — deploying a malicious container into the environment.
- [T1525 — Implant Container Image](https://attack.mitre.org/techniques/T1525/) — compromising container images in the registry.
- [T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) — finding secrets in container images, env vars, kubeconfig.
- [T1562.007 — Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) — disabling security controls in cloud environments.
- [CAPEC-512: Resource Depletion](https://capec.mitre.org/data/definitions/512.html) — cloud resource exhaustion via auto-scaling abuse.

See also: [OWASP Docker Security](https://github.com/OWASP/Docker-Security), [OWASP Cloud Security](https://github.com/OWASP/www-project-cloud-security)
