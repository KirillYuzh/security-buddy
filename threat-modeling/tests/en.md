# Threat Modeling Tests

| Check | Method |
| :--- | :--- |
| Data flow completeness | Every trust boundary must have a modeled threat |
| Attack tree coverage | Each high-risk branch should have a test scenario |
| CI/CD gate | Run `pytm --generate` on architecture changes, review report |