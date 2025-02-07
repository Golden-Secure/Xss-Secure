import os
import time
import sys
import logging
import asyncio
import requests
import json
import re
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from colorama import Fore
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
import urllib3


patterns = [
    "q=", "s=", "search=", "lang=", "keyword=", "query=", "page=", "keywords=", "year=", "view=", 
    "email=", "type=", "name=", "p=", "callback=", "jsonp=", "api_key=", "api=", "password=", "email=", 
    "emailto=", "token=", "username=", "csrf_token=", "unsubscribe_token=", "id=", "item=", "page_id=", 
    "month=", "immagine=", "list_type=", "url=", "terms=", "categoryid=", "key=", "l=", "begindate=", "enddate="
]

def fetch_old_urls(domain):
    sources = [
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    ]
    urls = set()
    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            if response.status_code == 200:
                if "urlscan" in source:
                    results = json.loads(response.text).get("results", [])
                    for result in results:
                        if "task" in result and "url" in result["task"]:
                            urls.add(result["task"]["url"])
                elif "alienvault" in source:
                    data = json.loads(response.text)
                    if "url_list" in data:
                        urls.update(url["url"] for url in data["url_list"] if "url" in url)
                else:
                    extracted_urls = [entry[0] for entry in json.loads(response.text)][1:]
                    urls.update(extracted_urls)
        except (requests.RequestException, json.JSONDecodeError):
            pass
    

    filtered_urls = []
    for url in urls:
        if any(pattern in url for pattern in patterns):
            filtered_urls.append(url)
    
    return list(set(filtered_urls))

def filter_xss_vulnerable_urls(urls):
    xss_patterns = [r'<script>', r'javascript:', r'onmouseover', r'onerror']
    return [url for url in urls if any(re.search(pattern, url, re.IGNORECASE) for pattern in xss_patterns)]

def remove_duplicates(urls):
    return list(set(urls))

def load_xss_payloads(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(payloads)} payloads from the file.")
            return payloads
    except FileNotFoundError:
        return []

def generate_payload_urls(url, payload):
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

def test_xss_payloads(urls, payloads):
    exploitable_urls = []
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver_service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=driver_service, options=chrome_options)

    all_urls_to_test = []

    # Generate all payload URLs to test
    for url in track(urls, description="Processing URLs..."):
        for payload in payloads:
            payload_urls = generate_payload_urls(url, payload)
            all_urls_to_test.extend(payload_urls)

    for idx, payload_url in enumerate(track(all_urls_to_test, description="Testing Payloads...")):
        try:
            driver.get(payload_url)
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert_text = alert.text
                if alert_text:
                    exploitable_urls.append(payload_url)
                    print(Fore.RED + f"[!] XSS Vulnerability Found!" + Fore.CYAN + f" Testing payload: {payload_url}")
                    break  # Stop testing further payloads for this URL, move to the next one
                alert.accept()
            except TimeoutException:
                pass
        except UnexpectedAlertPresentException:
            continue

        #print(Fore.CYAN + f"[{idx+1}/{len(all_urls_to_test)}] Testing payload: {payload_url}")

    driver.quit()

    report_date = time.strftime('%Y-%m-%d %H:%M:%S')

    report_html = f"""
<html><head>
            <title>XSS Vulnerability Report - Golden Secure</title>
 <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #1c1c1c;
            color: white;
            margin: 0;
            padding: 0;
        }}
        h1 {{
            color: #FFD700;
        }}
        .report-section {{
            margin: 20px;
            padding: 10px;
            border: 1px solid #FFD700;
            border-radius: 5px;
            background-color: #2a2a2a;
        }}
        .report-section h2 {{
            color: #FFD700;
        }}
        .url-list {{
            list-style-type: none;
            padding: 0;
        }}
        .url-list li {{
            padding: 5px;
            background-color: #333333;
            margin-bottom: 5px;
            border-radius: 5px;
        }}
        .url-list li a {{
            color: #FFD700;
            text-decoration: none;
        }}
        .url-list li a:hover {{
            text-decoration: underline;
        }}
    </style>
        </head>
        <body>
            <div class="report-section">
                <h1>XSS Vulnerability Report</h1>
                <h2>Golden Secure Report</h2>
                <p>Report generated on: {report_date} </p>
                <h2>Exploitable XSS URLs</h2>
    """

    for url in exploitable_urls:
        report_html += f"<li><a href='{url}' target='_blank'>{url}</a></li>"

    report_html += """
            </ul>
        </body>
    </html>
    """
    with open("xss_report.html", "w") as report_file:
        report_file.write(report_html)

    return exploitable_urls

def prompt_for_domains():
    while True:
        domain_input = input(Fore.CYAN + "[?] Enter a single domain or List from txt: ").strip()
        if domain_input:
            if os.path.isfile(domain_input):
                with open(domain_input, 'r') as file:
                    domains = [line.strip() for line in file if line.strip()]
                return domains

            elif ',' in domain_input:
                domains = [domain.strip() for domain in domain_input.split(',')]
                return domains

            else:
                return [domain_input]
        else:
            print(Fore.RED + "[!] You must provide either a file with domains, a single domain, or a comma-separated list of domains.")

def main():
    console = Console()
    panel = Panel(""" 
    ██   ██ ███████ ███████       ███████ ███████  ██████ ██    ██ ██████  ███████
     ██ ██  ██      ██            ██      ██      ██      ██    ██ ██   ██ ██
      ███   ███████ ███████ █████ ███████ █████   ██      ██    ██ ██████  █████
     ██ ██       ██      ██            ██ ██      ██      ██    ██ ██   ██ ██
    ██   ██ ███████ ███████       ███████ ███████  ██████  ██████  ██   ██ ███████
                                  Golden-Secure  https://t.me/GoldenSecure
    """, style="bold green", border_style="blue", expand=False)
    console.print(panel)

    domains = prompt_for_domains()
    payload_file = input("Enter the path to the payloads file: ").strip()

    all_urls = []
    for domain in domains:
        domain_urls = fetch_old_urls(domain)
        print(Fore.YELLOW + f"Fetched ({len(domain_urls)}) URLs from {domain}.")
        filtered_urls = filter_xss_vulnerable_urls(domain_urls)
        print(Fore.BLUE + f"Filtered ({len(filtered_urls)}) potentially vulnerable URLs.")
        unique_urls = remove_duplicates(filtered_urls)
        print(Fore.YELLOW + f"Removed duplicates, ({len(unique_urls)}) unique URLs remain.")
        all_urls.extend(unique_urls)

    print(Fore.YELLOW + f"Testing ({len(all_urls)}) unique URLs with XSS payloads...")
    payloads = load_xss_payloads(payload_file)

    exploitable_urls = test_xss_payloads(all_urls, payloads)
    print(Fore.GREEN + f"Scan complete. {len(exploitable_urls)} exploitable XSS URLs identified. Report saved to xss_report.html")

if __name__ == "__main__":
    main()
