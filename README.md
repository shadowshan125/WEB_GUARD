# WebGuard

**WebGuard** is a professional, modular web vulnerability scanning framework built on top of **Django**. Designed to function entirely as a **terminal-based (CLI) tool**, it leverages Django's robust ORM for native database management of scan results, configuration management, and custom management commands. The framework performs asynchronous scanning, target intelligence gathering, and structured reporting.

## Features

*   **Django Architecture**: Utilizes Django's ORM to natively and historically persist all reconnaissance and scanning data, providing a significant advantage over standard text-based script outputs.
*   **Reconnaissance Engine**: Automates DNS resolution, IP identification, and basic technology stack/server banner grabbing.
*   **Crawler Engine**: Employs `asyncio` and `aiohttp` for rapid, asynchronous spidering to discover endpoints and extract HTML forms across the target.
*   **Vulnerability Assessment Engines**:
    *   **SQL Injection (SQLi)**: Performs heuristic error-based parameter injection checks.
    *   **Cross-Site Scripting (XSS)**: Identifies reflected payload inputs to detect XSS vulnerabilities.
    *   **Misconfigurations (Headers)**: Highlights missing crucial security protections like CSP, HSTS, and X-Frame-Options, as well as server version disclosures.
    *   **Custom Signatures (Nuclei-style)**: Parses YAML templates to dynamically match URL paths, status codes, and response bodies (e.g., detecting exposed `.env` or configuration files).
*   **Risk Scoring**: Automatically calculates and assigns severity scores (Critical, High, Medium, Low, Info) to findings, calculating an overall risk level for the scan.
*   **CLI Integration**: Operates seamlessly from the command line using unified `manage.py` commands (`recon`, `crawl`, `scan`).
*   **Reporting System**: Compiles robust JSON and stylized HTML reports, stored natively in the `/reports` directory for out-of-band analysis and sharing.

## Prerequisites

*   Python 3.10+
*   Virtual Environment (recommended)

## Installation

1.  **Clone or setup the directory:** Navigate to your project directory.
2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On Linux/macOS:
    source venv/bin/activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Initialize the database:** Apply Django migrations to set up the SQLite database backend.
    ```bash
    python manage.py makemigrations scanner
    python manage.py migrate
    ```

## Usage

WebGuard is operated entirely via specialized Django management commands.

### 1. Reconnaissance (Target Intelligence)
Gather initial information about a target, including DNS records, IP resolution, and HTTP Server headers.
```bash
python manage.py recon https://example.com
```

### 2. Web Crawling (Spidering)
Crawl the target to discover endpoints, links, and HTML forms. You can control the depth and maximum number of URLs.
```bash
python manage.py crawl https://example.com --depth 2 --max 100
```

### 3. Full Vulnerability Scan
Execute the full suite: Reconnaissance, Crawling, and active Vulnerability Assessment (SQLi, XSS, Headers, Signatures).
```bash
python manage.py scan https://example.com --full-scan
```
*Note: You can omit `--full-scan` to run the active scan on just the base target URL without prior deep crawling.*

## Output & Reports

Upon completion of a scan, WebGuard securely logs finding directly into its local `.sqlite3` database.

Additionally, it generates structured reports detailing the findings, proofs of concept, and remediation steps. These are saved automatically in the `reports/` directory at the project root:
*   `reports/webguard_report_<domain>_<timestamp>.json`
*   `reports/webguard_report_<domain>_<timestamp>.html`

## Adding Custom Payloads & Signatures

WebGuard's modular nature allows for easy expansion:
*   **Wordlists**: Add standard payload strings (one per line) to `scanner/payloads/sqli.txt` or `scanner/payloads/xss.txt`.
*   **Signatures**: Add new Nuclei-style YAML templates in `scanner/payloads/templates/` to detect specific files, CVES, or misconfigurations based on path, HTTP method, and response body matchers.

## Disclaimer

**WebGuard is intended for educational and authorized security testing purposes only.** 
Do not use this tool against infrastructure or applications that you do not own or have explicit, written permission to test.
