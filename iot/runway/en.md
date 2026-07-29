# IoT Security Tests

| Check | Tools |
| :--- | :--- |
| Firmware extraction | `binwalk`, `firmwalker` |
| Port/service scanning | `nmap`, `masscan` |
| Protocol fuzzing | `Boofuzz`, `Scapy` |
| Update verification | Inspect signature scheme, test rollback |
| Physical attack surface | Identify UART/JTAG/SPI interfaces |
| Web interface | OWASP ZAP against embedded web server |
</content>
</｜｜DSML｜｜_file>
<write_to_file>
<path>iot/runway/en.md</path>
<content># IoT Security Runway

1. **Secure by Default** — ship devices with security features enabled (no "change password on first login").
2. **OTA Updates** — design a signed, encrypted update pipeline from day one.
3. **Least Privilege** — constrain network access to only needed services (no unnecessary open ports).
4. **Monitoring** — implement device telemetry for anomaly detection.
5. **Lifecycle Management** — plan for end-of-life decommissioning.

Reference: [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things-top-10/)