# DevSecOps Tests

| Check | Tool |
| :--- | :--- |
| CI/CD secret scanning | `truffleHog`, `gitleaks`, `ggshield` |
| Pipeline configuration audit | `conftest` (policy against YAML), `checkov` |
| SBOM generation | `cyclonedx-bom`, `trivy` |
| Dependency tracking | Dependency-Track API integration |
| Scan orchestration | SecureCodeBox, Glue automation |

Goal: every pull request triggers SAST/SCA/secret scan and reports to DefectDojo.