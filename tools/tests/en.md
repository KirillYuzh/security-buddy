# Tools — Test Integration

| Tool | CI/CD Integration |
| :--- | :--- |
| ZAP | `zap-full-scan.py` vs staging; API mode for headless |
| Amass | `amass enum` weekly; diff new subdomains |
| Dependency-Check | `dependency-check --scan` every build; fail on CVSS≥7 |
| Nettacker | Network scan on staging environment changes |
| O-Saft | TLS check before production release |
| SecureTea | Deploy as sidecar on IoT/edge devices |

See [general/tests](../general/tests/en.md) for overarching testing methodology.