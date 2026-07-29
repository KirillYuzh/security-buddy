# API Vulnerabilities & Mitigations

The [OWASP API Security Top 10](https://github.com/OWASP/API-Security) is the authoritative list:

- **API1:2023 — Broken Object Level Authorization** — test that user A cannot access user B's objects.
- **API2:2023 — Broken Authentication** — verify token validation, rotation, and expiry.
- **API3:2023 — Broken Object Property Level Authorization** — ensure APIs don't expose excessive properties.
- **API4:2023 — Unrestricted Resource Consumption** — enforce rate limits, pagination, and payload size limits.
- **API5:2023 — Broken Function Level Authorization** — test admin endpoints accessible by regular users.
- **API6:2023 — Unrestricted Access to Sensitive Business Flows** — prevent automated abuse.
- **API7:2023 — Server Side Request Forgery** — validate all redirects and external URL calls.
- **API8:2023 — Security Misconfiguration** — disable verbose error messages, unused HTTP methods.
- **API9:2023 — Improper Inventory Management** — decommission old API versions, document all endpoints.
- **API10:2023 — Unsafe Consumption of APIs** — validate and sanitize data from third-party APIs.

## Tools
- [OWASP ZAP](https://www.zaproxy.org/) — scan APIs by importing OpenAPI/SOAP/GraphQL specs.
- [OWASP Nettacker](https://github.com/OWASP/Nettacker) — discover hidden API endpoints.
- [OWASP Cheat Sheet: REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: GraphQL Security](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

See also: [OWASP API Security project page](https://owasp.org/www-project-api-security/)