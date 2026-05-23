# Web Application Vulnerability Scanner

A Python-based web vulnerability scanner that detects common OWASP Top 10 security issues in web applications.

## Features

- Security header analysis
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Open redirect detection
- Sensitive directory enumeration
- robots.txt analysis
- HTML + JSON report generation

## Tech Stack

- Python 3.11
- requests
- BeautifulSoup4
- colorama
- Flask (for test target app)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py http://target-url.com
```

## Sample Output

- Scans for 6 security header misconfigurations
- Detects SQLi and XSS via form injection
- Checks for open redirects across common parameters
- Brute-forces common sensitive directories
- Generates a timestamped HTML + JSON report

## Disclaimer

This tool is for **authorized testing and educational purposes only**.
Never scan websites you do not own or have explicit permission to test.
## Sample Report<img width="796" height="1746" alt="_C__Users_oanga_web-vuln-scanner_report_20260523_091130 html" src="https://github.com/user-attachments/assets/c1bb52ab-ee19-4aac-ae56-b146bc4f14e7" />
