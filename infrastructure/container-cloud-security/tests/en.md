# Container & Cloud Security Tests

| Check | Tools |
| :--- | :--- |
| Image vulnerability scan | `trivy image`, `grype`, `snyk` |
| Dockerfile linting | `hadolint`, `dockle` |
| Kubernetes manifest validation | `kubescape`, `kube-bench`, `polaris` |
| Runtime policy enforcement | `OPA/Gatekeeper`, `Kyverno` |
| Secret detection | `truffleHog`, `git-secrets` |
| Cloud config scanning | `checkov`, `tfsec` (Terraform), `prowler` (AWS) |

Run these in CI: `trivy image` on every build, `kubescape` on every manifest change.