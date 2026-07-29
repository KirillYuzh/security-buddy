# Vulnerabilities & Mitifations

Firstly, make sure that you understand all common vulnerabilities - read [OWASP Top 10](https://owasp.org/Top10/2025/).

# CVE, CWE

**CVE** (Common Vulnerabilities and Exposures) is a dictionary of publicly disclosed cybersecurity vulnerabilities. Each CVE entry has a unique identifier in the format `CVE-YYYY-NNNNN`. Think of it as a specific "incident report" for a known flaw. You can search CVEs at [cve.mitre.org](https://cve.mitre.org/) or via the [NVD (National Vulnerability Database)](https://nvd.nist.gov/).

**CWE** (Common Weakness Enumeration) is a taxonomy of common software and hardware weakness types. Each CWE entry has a unique identifier like `CWE-79` (Cross-Site Scripting). Think of it as a "category" or "class" of vulnerability. OWASP Top 10 entries map directly to CWEs. Explore the full list at [cwe.mitre.org](https://cwe.mitre.org/).

The relationship is simple: a **CWE** is the *type* of weakness, and a **CVE** is a *specific instance* of that weakness found in a real product. For example, `CVE-2023-44487` (HTTP/2 Rapid Reset attack) is an instance of the weakness class `CWE-770` (Allocation of Resources Without Limits or Throttling).

When assessing a finding in your reports:
1. Identify the **CWE** class (gives you the category of the issue).
2. Locate the matching **CVE** if one exists (tells you if there's a known exploit in the wild).
3. Use OWASP references to understand the mitigation.

Useful references:
- [OWASP CWE page](https://owasp.org/www-community/OWASP_CWE_Matrix)
- [NVD Search](https://nvd.nist.gov/)
- [CVE.org](https://www.cve.org/)

