# Supply Chain Security Tests

| Check | Tool | Cadence |
| :--- | :--- | :--- |
| Known vulnerabilities | `dependency-check`, `trivy fs` | Every build |
| SBOM generation | `cyclonedx-bom`, `trivy` | Every release |
| Outdated deps | `npm outdated`, `pip list --outdated` | Weekly |
| Provenance | `cosign verify`, `npm audit signatures` | Every build |
| License compliance | `license-checker`, `scancode` | Every merge |

1. Generate SBOM → feed into Dependency-Track.
2. Fail CI on critical CVEs in production dependencies.
3. Validate all third-party actions in CI/CD pipelines.