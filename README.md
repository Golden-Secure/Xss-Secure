# Xss-Secure Scanner - Golden Secure

## Overview
Golden Secure's XSS Vulnerability Scanner is a powerful cybersecurity tool designed to identify Cross-Site Scripting (XSS) vulnerabilities in web applications. The tool collects historical URLs associated with a domain, injects XSS payloads, and tests them using Selenium to detect exploitable XSS vulnerabilities.

## Features
- Fetches historical URLs from multiple sources (Wayback Machine, AlienVault, URLScan).
- Filters potentially vulnerable URLs using regex-based detection.
- Removes duplicate URLs to optimize testing.
- Loads custom XSS payloads from a user-defined file.
- Uses Selenium WebDriver to test XSS payload execution.
- Generates a detailed HTML report of exploitable URLs.

## Requirements
Ensure you have the following dependencies installed:

### Install Python
Ensure you have Python 3.x installed. You can download it from [Python.org](https://www.python.org/downloads/).

### Install Required Libraries
You can install all dependencies using the following command:

```bash
pip install -r requirements.txt
```

Or manually install the required libraries:

```bash
pip install requests
pip install selenium
pip install webdriver-manager
pip install colorama
pip install rich
pip install urllib3
```

## Installation
Clone the repository and navigate to the directory:

```bash
git clone https://github.com/GoldenSecure/Xss-Secure.git
cd Xss-Secure
```

## Usage
Run the tool and enter the target domain or provide a list of domains in a text file:

```bash
python Xss-Secure.py
```

### Input
When prompted, enter a domain or a path to a file containing domains:

```
[?] Enter a single domain or List from txt: example.com
```

Specify the path to the XSS payloads file:

```
Enter the path to the payloads file: payloads.txt
```

### Process
The tool will:
1. Fetch URLs related to the target domain.
2. Filter for potentially vulnerable URLs.
3. Test XSS payload execution.
4. Generate a report (`xss_report.html`).

## Example Report
After scanning, an HTML report (`xss_report.html`) is created, listing all exploitable URLs.

### Report Structure
The report contains:
- **Date and time** of the scan.
- **List of URLs** that are vulnerable.
- **Clickable links** for testing in browsers.

## Troubleshooting
### Selenium WebDriver Setup
If you encounter issues with Selenium, ensure you have the Chrome browser installed. You may need to manually install or update the ChromeDriver:

```bash
webdriver-manager update
```

If running on a server without a display, use the `--headless` option in Selenium settings.

## Disclaimer
This tool is intended for educational and ethical penetration testing purposes only. Unauthorized scanning of websites is illegal. The user assumes all responsibility for usage.

## Author
Dr.Mohamed A Jaber
Golden Secure - [Telegram](https://t.me/GoldenSecure)
