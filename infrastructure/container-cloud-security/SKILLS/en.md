# Container & Cloud Security Skills

- **Image Hardening** — use minimal base images, scan with Trivy/Grype, sign with cosign.
- **Runtime Security** — configure seccomp, AppArmor, read-only root filesystem.
- **Kubernetes RBAC** — least privilege for service accounts, namespaces, network policies.
- **Secrets Management** — use Vault, External Secrets Operator, never Kubernetes Secrets in plaintext.
- **Serverless** — validate event payloads, set function timeouts, disable unused API triggers.