# WAF & ModSecurity Tests

| Check | Tool/Method |
| :--- | :--- |
| CRS regression tests | `crs-toolchain`, `go-ftw` |
| WAF bypass testing | `wafw00f`, manual encoding fuzzing |
| AppSensor detection | Deploy detection points, verify alerts |
| Security headers | [securityheaders.com](https://securityheaders.com/), CLI scan |
</content>
</｜｜DSML｜｜_file>
<write_to_file>
<path>infrastructure/waf-modsecurity/runway/en.md</path>
<content># WAF & ModSecurity Runway

1. **Deploy in blocking mode only after tuning** — start with log-only mode, tune CRS exclusions, then enable blocking.
2. **Monitor bypass attempts** — track blocked vs. allowed suspicious requests; adjust rules.
3. **Layer with AppSensor** — perimeter WAF + application-level detection for defense in depth.
4. **Update CRS regularly** — pin to a stable release, test against staging before updating production.

Reference: [ModSecurity Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/ModSecurity_Cheat_Sheet.html)