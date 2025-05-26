

import subprocess
import sys
import requests
from urllib.parse import urljoin, urlparse
import re
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_scanner.log'),
        logging.StreamHandler()
    ]
)


def install_packages():

    required_packages = {
        'beautifulsoup4': 'bs4',
        'requests': 'requests'
    }

    for pkg, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            logging.info(f"Installing missing package: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

            if import_name in sys.modules:
                del sys.modules[import_name]
            __import__(import_name)


install_packages()
from bs4 import BeautifulSoup

PATTERNS = {
    "Email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    "Phone": r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "IP Address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "Credit Card": r'\b(?:\d[ -]*?){13,16}\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "API Key": r'\b[a-zA-Z0-9]{32,}\b'
}

VULNERABILITY_SIGNATURES = {
    "SQL Injection": [
        r'(\'|\")(\s*?(select|union|insert|update|delete|drop|alter|create|exec)\b|\b(and|or)\s+[\w]+\s*=\s*[\w]+)',
        r'\/\*.*\*\/',
        r'--\s'
    ],
    "XSS": [
        r'<script\b[^>]*>.*<\/script>',
        r'onerror\s*=\s*["\'].*["\']',
        r'javascript:'
    ]
}

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}


class WebScanner:
    def __init__(self, base_url, max_threads=5, max_pages=20, rate_limit=1.0):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.max_threads = max_threads
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.results = {
            'base_url': base_url,
            'scanned_pages': [],
            'sensitive_data': {},
            'vulnerabilities': {},
            'forms': {}
        }

    def _is_valid_url(self, url):

        parsed = urlparse(url)
        return (parsed.netloc == self.domain and
                parsed.scheme in ('http', 'https') and
                not any(ext in parsed.path for ext in ('.jpg', '.png', '.css', '.js')))

    def _get_links(self, url):

        try:
            time.sleep(self.rate_limit * random.uniform(0.5, 1.5))
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()

            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag['href']
                full_url = urljoin(url, href)
                if self._is_valid_url(full_url):
                    links.add(full_url)

            return links

        except requests.RequestException as e:
            logging.warning(f"Error fetching {url}: {e}")
            return set()

    def crawl(self):

        logging.info(f"Starting crawl of {self.base_url}")
        to_visit = {self.base_url}
        discovered_urls = set()

        while to_visit and len(discovered_urls) < self.max_pages:
            current_url = to_visit.pop()
            if current_url in self.visited_urls:
                continue

            self.visited_urls.add(current_url)
            new_links = self._get_links(current_url)
            discovered_urls.update(new_links)
            to_visit.update(new_links - self.visited_urls)

        logging.info(f"Crawling complete. Found {len(discovered_urls)} pages.")
        return discovered_urls

    def scan_page(self, url):

        try:
            time.sleep(self.rate_limit)
            logging.info(f"Scanning: {url}")

            response = self.session.get(url, timeout=15)
            response.raise_for_status()

            sensitive_data = {}
            text = BeautifulSoup(response.text, 'html.parser').get_text()
            for label, pattern in PATTERNS.items():
                matches = set(re.findall(pattern, text, re.IGNORECASE))
                if matches:
                    sensitive_data[label] = list(matches)

            forms = []
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_info = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_info['inputs'].append({
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    })
                forms.append(form_info)

            vulnerabilities = {}
            for vuln_type, patterns in VULNERABILITY_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        if vuln_type not in vulnerabilities:
                            vulnerabilities[vuln_type] = []
                        vulnerabilities[vuln_type].append(f"Pattern: {pattern}")

            self.results['scanned_pages'].append(url)
            if sensitive_data:
                self.results['sensitive_data'][url] = sensitive_data
            if forms:
                self.results['forms'][url] = forms
            if vulnerabilities:
                self.results['vulnerabilities'][url] = vulnerabilities

            return True

        except requests.RequestException as e:
            logging.error(f"Failed to scan {url}: {e}")
            return False

    def scan_website(self):

        start_time = time.time()
        urls_to_scan = self.crawl()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_page, url): url for url in urls_to_scan}
            for future in as_completed(futures):
                future.result()

        self.results['scan_time'] = time.time() - start_time
        self.results['pages_scanned'] = len(self.results['scanned_pages'])
        self.generate_report()

        return self.results

    def generate_report(self, filename='scan_report.json'):

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        logging.info(f"Report saved to {filename}")


def main():
    print("=== Web Vulnerability Scanner ===")
    target_url = input("Enter target URL (e.g., http://example.com): ").strip()

    scanner = WebScanner(
        base_url=target_url,
        max_threads=5,
        max_pages=20,
        rate_limit=0.5
    )

    print("\nStarting scan...")
    results = scanner.scan_website()

    print("\n=== Scan Results ===")
    print(f"Pages scanned: {results['pages_scanned']}")
    print(f"Sensitive data found on {len(results['sensitive_data'])} pages")
    print(f"Vulnerabilities found on {len(results['vulnerabilities'])} pages")
    print(f"Report saved to scan_report.json")


if __name__ == "__main__":
    main()