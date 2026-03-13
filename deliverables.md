# WebGuard Vulnerability Scanner - Deliverables Report

## 1. Abstract
The goal of this project was to design and implement **WebGuard**, a professional modular web vulnerability scanning framework built on Django. The tool automatically detects exposed configurations, mapping the target's attack surface using asynchronous web crawling, fingerprints server technologies, and actively probes for high-impact flaws like SQL Injection (SQLi) and Cross-Site Scripting (XSS). This terminal-based utility allows security engineers and penetration testers to execute fast, reliable scans resulting in structured reports (JSON and HTML) without leaving the command line.

## 2. Research Section
**Target application:** Example Vulnerable Application (`testphp.vulnweb.com`)
**URL:** http://testphp.vulnweb.com/
**Category:** Web Application Security Practice Hub
**Popularity:** Maintained by Acunetix specifically as a testing ground for automated scanners.
**Technology Stack (detected):** Nginx, PHP

## 3. Data Collection
During the automated scanning execution, WebGuard detected the following:
* **Endpoints:** Discovered multiple endpoints through asynchronous crawling (e.g., `/search.php`, `/artists.php`, `/login.php`).
* **Forms:** Identified several HTML forms, analyzing their methods and input parameters (e.g., search forms and login fields).
* **Technologies:** Identified Nginx as the primary web server based on the `Server` header.

## 4. Impact Analysis (Sample Vulnerabilities)
The vulnerabilities detected pose severe threats to the confidentiality and integrity of a real-world web application:

1. **SQL Injection (SQLi) - CRITICAL**
   * **Impact:** An attacker can manipulate database queries (e.g., via the `artist` parameter). This can result in data exfiltration, authentication bypass, or full database compromise.
2. **Reflected Cross-Site Scripting (XSS) - HIGH**
   * **Impact:** User input is reflected back into the browser un-sanitized. An attacker could craft malicious links which, when clicked by a victim, execute arbitrary JavaScript. This leads to session hijacking or unauthorized actions on behalf of the victim.
3. **Missing Security Headers - LOW**
   * **Impact:** Lack of headers like `Content-Security-Policy` and `Strict-Transport-Security` increases the overall exposure to downgrade attacks and XSS impact.

## 5. Recommendations
* **Input Validation & Parameterization:** For SQLi, immediately enforce prepared statements using Object Relational Mapping (ORM) frameworks or parameterized queries rather than concatenating user input directly into SQL strings.
* **Context-Aware Output Encoding:** For XSS, strictly encode output rendered in the HTML response depending on its context (HTML body, attributes, Javascript string). Use modern frameworks that auto-escape variables.
* **Security Headers Policies:** Web servers should be configured to emit modern security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) to protect clients.
* **Minimize Information Disclosure:** Strip or genericize the `Server` and `X-Powered-By` headers to prevent fingerprinting.

## 6. Proof of Concept (Scanner Execution)
CLI usage flow demonstrated:
```bash
> python manage.py scan http://testphp.vulnweb.com/ --full-scan
[*] Starting WebGuard Security Scan on http://testphp.vulnweb.com/...
[*] [Phase 1] Target Intelligence Gathering
[+] Intel gathered. IP: 44.228.249.3, Technologies: []
[*] [Phase 2] Web Crawling (Depth: 2, Max: 100)
[+] Discovered 45 unique internal endpoints.
[*] [Phase 3] Vulnerability Assessment
[*] Starting vulnerability scans on 45 endpoints...
[INFO] Server Version Disclosure found at http://testphp.vulnweb.com/
[LOW] Missing Security Header: Strict-Transport-Security found at http://testphp.vulnweb.com/
[CRITICAL] SQL Injection (Error Based) found at http://testphp.vulnweb.com/listproducts.php
[HIGH] Reflected Cross-Site Scripting (XSS) found at http://testphp.vulnweb.com/search.php
[*] Scan complete. Overall Risk Level: CRITICAL
[*] [Phase 4] Report Generation
[+] JSON Report generated: reports\webguard_report_testphp.vulnweb.com_date.json
[+] HTML Report generated: reports\webguard_report_testphp.vulnweb.com_date.html
[SUCCESS] Scan successfully completed. View reports in the reports/ directory.
```

## 7. Structure & Code
The full Django framework resides in the `WebGuard` directory:
- `manage.py` - Core entry point
- `scanner/management/commands/` - CLI interface
- `scanner/core/` - Crawling and Intelligence
- `scanner/engine/` - Risk scoring, Signature matching, and Orchestrator
- `scanner/modules/` - Detection logic for SQLi, XSS, and misconfigurations
- `scanner/report/` - Generation of JSON/HTML analysis documents

## 8. References
1. **OWASP Top 10 (2021):** Fundamental knowledge base for web application vulnerabilities (Injection, XSS, Misconfigurations). https://owasp.org/Top10/
2. **Django Documentation:** For leveraging ORM and management commands as a Python CLI. https://docs.djangoproject.com/
3. **aiohttp Documentation:** Used to vastly improve crawler/scanner performance via event loops. https://docs.aiohttp.org/
4. **Nuclei (ProjectDiscovery):** Used as inspiration for the `SignatureEngine` parsing YAML signatures. https://github.com/projectdiscovery/nuclei
