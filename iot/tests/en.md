# IoT Security Tests

| Check | Tools |
| :--- | :--- |
| Firmware extraction | `binwalk`, `firmwalker` |
| Port/service scanning | `nmap`, `masscan` |
| Protocol fuzzing | `Boofuzz`, `Scapy` |
| Update verification | Inspect signature scheme, test rollback |
| Physical attack surface | Identify UART/JTAG/SPI interfaces |
| Web interface | OWASP ZAP against embedded web server |