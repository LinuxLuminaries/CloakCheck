import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
from colorama import Fore, Style, init
import re
import urllib3

# Initialize colorama
init(autoreset=True)

# List of security headers to check (including Pragma and Cache-Control)
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Cache-Control",
    "Pragma"
]

def check_security_headers(url, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)  # Use SSL verification flag
        headers = response.headers

        # Check for missing headers
        missing_headers = [header for header in SECURITY_HEADERS if header not in headers]
        
        misconfigurations = []

        # Check for potential misconfigurations
        if "Cache-Control" in headers:
            cache_control = headers["Cache-Control"].lower()
            if not any(value in cache_control for value in ["no-store", "no-cache"]):
                misconfigurations.append(f"Cache-Control should include 'no-store' or 'no-cache'. Original: {headers['Cache-Control']}")

        if "Pragma" in headers:
            pragma = headers["Pragma"].lower()
            if pragma != "no-cache":
                misconfigurations.append(f"Pragma should be set to 'no-cache'. Original: {headers['Pragma']}")

        if "X-Content-Type-Options" in headers:
            if headers["X-Content-Type-Options"].lower() != "nosniff":
                misconfigurations.append(f"X-Content-Type-Options should be set to 'nosniff'. Original: {headers['X-Content-Type-Options']}")

        if "Strict-Transport-Security" in headers:
            sts = headers["Strict-Transport-Security"].lower()
            if "max-age" not in sts or int(re.search(r"max-age=(\d+)", sts).group(1)) < 31536000:
                misconfigurations.append(f"Strict-Transport-Security should have 'max-age' of at least 31536000 (1 year). Original: {headers['Strict-Transport-Security']}")
            if "includesubdomains" not in sts:
                misconfigurations.append(f"Strict-Transport-Security should include 'includeSubDomains'. Original: {headers['Strict-Transport-Security']}")

        # Report results
        if missing_headers:
            print(f"{Fore.LIGHTRED_EX}[!] {Fore.LIGHTBLUE_EX}Missing Security Headers for URL: {url}")
            print(f"{Fore.LIGHTGREEN_EX}Missing Headers: {missing_headers}\n")
        elif misconfigurations:
            print(f"{Fore.LIGHTRED_EX}[!] {Fore.LIGHTBLUE_EX}Potential Misconfigurations for URL: {url}")
            print(f"{Fore.LIGHTGREEN_EX}Misconfigurations: {misconfigurations}\n")
        else:
            print(f"{Fore.LIGHTGREEN_EX}[+] All Security Headers Present and Properly Configured for URL: {url}\n")
        return url if missing_headers or misconfigurations else None

    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTRED_EX}[!] Could not fetch {url}. Error: {str(e)}")
    return None

def find_urls_in_page(url, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)  # Use SSL verification flag
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all href links on the page
        urls = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)  # Handle relative URLs
            # Ensure it's a valid URL
            if urlparse(full_url).scheme in ['http', 'https']:
                urls.add(full_url)

        return urls
    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTRED_EX}[!] Could not crawl {url}. Error: {str(e)}")
        return set()

def crawl_and_check(url, crawl_all=False, verify_ssl=True):
    if crawl_all:
        urls_to_check = find_urls_in_page(url, verify_ssl=verify_ssl)
        urls_to_check.add(url)  # Add the main URL to be checked
        print(f"{Fore.LIGHTBLUE_EX}[*] Found {len(urls_to_check)} URLs. Checking for security headers...\n")
    else:
        urls_to_check = {url}
        print(f"{Fore.LIGHTBLUE_EX}[*] Checking security headers for the provided URL: {url}\n")

    insecure_urls = []
    for url in urls_to_check:
        result = check_security_headers(url, verify_ssl=verify_ssl)
        if result:
            insecure_urls.append(result)

    if insecure_urls:
        print(f"{Fore.LIGHTRED_EX}[!] URLs with missing or misconfigured security headers:")
        for insecure_url in insecure_urls:
            print(f"{Fore.LIGHTBLUE_EX}{insecure_url}")
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] All URLs have the required security headers and configurations!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crawl a website and check for missing or misconfigured security headers")
    parser.add_argument("-u", "--url", required=True, help="URL of the website to check or crawl")
    parser.add_argument("-A", "--All", action="store_true", help="Crawl all URLs in the page instead of checking just the given URL")
    parser.add_argument("-b", "--bypass", action="store_true", help="Bypass SSL certificate verification")

    args = parser.parse_args()

    # Disable SSL warnings if bypassing SSL verification
    if args.bypass:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Call the crawl_and_check function with the SSL bypass flag
    crawl_and_check(args.url, crawl_all=args.All, verify_ssl=not args.bypass)
