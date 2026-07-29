# API Security Tests

| Test Type | Tools | What It Covers |
| :--- | :--- | :--- |
| **SAST** | `semgrep`, custom rules | Hardcoded API keys, insecure endpoint definitions |
| **DAST** | `ZAP`, `nuclei` | Broken object auth, injection, rate limiting gaps |
| **Fuzzing** | `ZAP fuzzer`, `Burp Intruder` | Input validation, schema enforcement |
| **Auth Testing** | `oauth2-proxy`, custom scripts | Token validation, OAuth/OIDC misconfig |
| **Schema Validation** | `openapi-enforcer`, `spectral` | Contract compliance |

## CI/CD gates
1. Import OpenAPI spec into ZAP and run automated scan before staging deploy.
2. Run `nuclei -t http/exposed-panels/` and custom API templates.
3. Validate OpenAPI contract compliance with spectral linting.