# API Security Skills

Core competencies for API security:

- **API Discovery & Inventory** — maintain a complete catalog of all API endpoints (including shadow APIs).
- **Authentication & Authorization Design** — implement OAuth 2.0 / OIDC correctly, enforce least privilege per endpoint.
- **Input Validation & Schema Enforcement** — validate all inputs against OpenAPI/JSON Schema. Reject malformed payloads.
- **Rate Limiting & Throttling** — prevent abuse and resource exhaustion.
- **Secrets Management** — never hardcode API keys in source code.

Use [OWASP ZAP](https://www.zaproxy.org/) with OpenAPI imports for automated testing.
