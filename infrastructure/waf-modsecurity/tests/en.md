# WAF & ModSecurity Tests

| Check | Tool/Method |
| :--- | :--- |
| CRS regression tests | `crs-toolchain`, `go-ftw` |
| WAF bypass testing | `wafw00f`, manual encoding fuzzing |
| AppSensor detection | Deploy detection points, verify alerts |
| Security headers | [securityheaders.com](https://securityheaders.com/), CLI scan |