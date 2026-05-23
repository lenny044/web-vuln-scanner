import argparse
import sys
from urllib.parse import urljoin, urlparse
from utils import (print_info, print_success, print_warning,
                   print_error, get_page, get_all_forms,
                   get_form_details, submit_form)
from report import generate_report

vulnerabilities = []

def add_vuln(vuln_type, severity, details):
    vulnerabilities.append({
        "type": vuln_type,
        "severity": severity,
        "details": details
    })

def check_headers(url):
    print_info("Checking security headers...")
    response = get_page(url)
    if response is None:
        return

    headers = response.headers
    security_headers = {
        "X-Frame-Options": ("Missing X-Frame-Options header — site may be vulnerable to clickjacking", "Medium"),
        "X-Content-Type-Options": ("Missing X-Content-Type-Options header — MIME sniffing possible", "Low"),
        "Content-Security-Policy": ("Missing Content-Security-Policy header — XSS risk increased", "High"),
        "Strict-Transport-Security": ("Missing HSTS header — connection may be downgraded to HTTP", "Medium"),
        "X-XSS-Protection": ("Missing X-XSS-Protection header", "Low"),
        "Referrer-Policy": ("Missing Referrer-Policy header — may leak sensitive URL data", "Low"),
    }

    for header, (message, severity) in security_headers.items():
        if header not in headers:
            print_warning(message)
            add_vuln(f"Missing Header: {header}", severity, message)
        else:
            print_success(f"{header} is present")

def check_robots(url):
    print_info("Checking robots.txt...")
    robots_url = urljoin(url, "/robots.txt")
    response = get_page(robots_url)
    if response and response.status_code == 200:
        print_warning("robots.txt found — reviewing for sensitive paths...")
        lines = response.text.splitlines()
        sensitive_keywords = ["admin", "backup", "config", "login", "private", "secret", "db"]
        for line in lines:
            for keyword in sensitive_keywords:
                if keyword in line.lower():
                    msg = f"Sensitive path in robots.txt: {line.strip()}"
                    print_warning(msg)
                    add_vuln("Sensitive Path in robots.txt", "Medium", msg)
    else:
        print_info("No robots.txt found")

def check_sql_injection(url):
    print_info("Testing for SQL Injection...")
    payloads = ["'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\""]
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql syntax",
        "syntax error"
    ]

    forms = get_all_forms(url)
    print_info(f"Found {len(forms)} form(s) on {url}")

    for form in forms:
        details = get_form_details(form)
        for payload in payloads:
            response = submit_form(details, url, payload)
            if response is None:
                continue
            for sig in error_signatures:
                if sig in response.content.decode("utf-8", errors="ignore").lower():
                    msg = f"SQL Injection detected with payload: {payload}"
                    print_warning(msg)
                    add_vuln("SQL Injection", "High", msg)
                    break

def check_xss(url):
    print_info("Testing for Cross-Site Scripting (XSS)...")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]

    forms = get_all_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in payloads:
            response = submit_form(details, url, payload)
            if response is None:
                continue
            if payload in response.content.decode("utf-8", errors="ignore"):
                msg = f"XSS vulnerability detected with payload: {payload}"
                print_warning(msg)
                add_vuln("Cross-Site Scripting (XSS)", "High", msg)
                break

def check_open_redirects(url):
    print_info("Checking for open redirects...")
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com"
    ]
    parsed = urlparse(url)
    redirect_params = ["redirect", "url", "next", "return", "goto", "target"]

    for param in redirect_params:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = get_page(test_url)
            if response is None:
                continue
            if response.url and "evil.com" in response.url:
                msg = f"Open redirect via param '{param}' to {payload}"
                print_warning(msg)
                add_vuln("Open Redirect", "Medium", msg)

def check_directory_listing(url):
    print_info("Checking for exposed directories...")
    common_dirs = [
        "/admin", "/backup", "/config", "/uploads",
        "/files", "/db", "/logs", "/test", "/private", "/.git"
    ]

    for directory in common_dirs:
        test_url = urljoin(url, directory)
        response = get_page(test_url)
        if response is None:
            continue
        if response.status_code == 200:
            msg = f"Exposed directory found: {test_url} (Status: 200)"
            print_warning(msg)
            add_vuln("Exposed Directory", "Medium", msg)
        elif response.status_code == 403:
            print_info(f"Directory exists but forbidden: {test_url} (403)")

def run_scan(url):
    print_info(f"Starting scan on: {url}")
    print_info("=" * 50)

    check_headers(url)
    print()
    check_robots(url)
    print()
    check_sql_injection(url)
    print()
    check_xss(url)
    print()
    check_open_redirects(url)
    print()
    check_directory_listing(url)

    print()
    print_info("=" * 50)
    print_info(f"Scan complete. {len(vulnerabilities)} issue(s) found.")
    print()

    html_file, json_file = generate_report(url, vulnerabilities)
    print_success(f"HTML report saved: {html_file}")
    print_success(f"JSON report saved: {json_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner"
    )
    parser.add_argument("url", help="Target URL to scan (e.g. http://example.com)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "http://" + url

    run_scan(url)

if __name__ == "__main__":
    main()