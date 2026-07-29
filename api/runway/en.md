# API Security Runway

Design APIs with security from the start:

1. **Inventory** — document all endpoints in an OpenAPI spec. Keep it in the same repo as the code.
2. **Authz-first** — implement authorization at the API gateway level (not only in the app).
3. **Schema-first** — validate every request against the OpenAPI schema before business logic.
4. **Versioning** — never remove an API version without deprecation notices; maintain VWAD-like inventory.
5. **Monitoring** — log all auth failures, unexpected 4xx/5xx, and unusual payload sizes.

Reference: [OWASP DevGuide — API Security Chapter](https://devguide.owasp.org/)