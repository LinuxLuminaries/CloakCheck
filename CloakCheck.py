import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
from colorama import Fore, Style, init
import re
import urllib3

init(autoreset=True)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Cache-Control",
    "Pragma",
    "Referrer-Policy",
    "Feature-Policy",
    "Access-Control-Allow-Origin"
]

def get_recommendations(header):
    recommendations = {
        "Cache-Control": "Ensure Cache-Control includes 'no-store' or 'no-cache' to prevent sensitive information from being stored.",
        "Pragma": "Set Pragma to 'no-cache' to control caching behavior.",
        "X-Content-Type-Options": "Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing.",
        "Strict-Transport-Security": (
            "Configure Strict-Transport-Security with a 'max-age' of at least 31536000 (1 year) "
            "and include 'includeSubDomains' to enforce security across all subdomains."
        ),
        "Referrer-Policy": "Set a Referrer-Policy to control how much referrer information is passed when navigating.",
        "Feature-Policy": "Define a Feature-Policy to control which features can be used in the web application.",
        "Access-Control-Allow-Origin": "Configure Access-Control-Allow-Origin to restrict which domains can access resources."
    }
    return recommendations.get(header, "No specific recommendation available.")

def check_security_headers(url, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        headers = response.headers

        missing_headers = [header for header in SECURITY_HEADERS if header not in headers]
        misconfigurations = []

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

        if "Referrer-Policy" in headers:
            if headers["Referrer-Policy"].lower() not in ["no-referrer", "same-origin", "strict-origin-when-cross-origin"]:
                misconfigurations.append(f"Referrer-Policy should be configured for privacy. Original: {headers['Referrer-Policy']}")

        if "Feature-Policy" in headers:
            if "geolocation" in headers["Feature-Policy"].lower():
                misconfigurations.append("Feature-Policy should limit geolocation access based on your application's needs.")

        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] != "*":
                misconfigurations.append("Access-Control-Allow-Origin should be configured properly to avoid CORS issues.")

        if missing_headers:
            print(f"{Fore.LIGHTRED_EX}[!] {Fore.LIGHTBLUE_EX}Missing Security Headers for URL: {url}")
            print(f"{Fore.LIGHTGREEN_EX}Missing Headers: {missing_headers}\n")
            for header in missing_headers:
                print(f"  - Issue: Missing {Fore.LIGHTGREEN_EX}{header}{Fore.RESET} - Recommendation: {Fore.LIGHTGREEN_EX}{get_recommendations(header)}{Fore.RESET}")

        elif misconfigurations:
            print(f"{Fore.LIGHTRED_EX}[!] {Fore.LIGHTBLUE_EX}Potential Misconfigurations for URL: {url}")
            print(f"{Fore.LIGHTGREEN_EX}Misconfigurations: {misconfigurations}\n")
            for misconfig in misconfigurations:
                issue_header = misconfig.split()[0]
                print(f"{Fore.LIGHTCYAN_EX}  - Issue: {misconfig} - Recommendation: {get_recommendations(issue_header)}")

        else:
            print(f"{Fore.LIGHTGREEN_EX}[+] All Security Headers Present and Properly Configured for URL: {url}\n")
        return url if missing_headers or misconfigurations else None

    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTRED_EX}[!] Could not fetch {url}. Error: {str(e)}")
    return None

def find_urls_in_page(url, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        urls = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).scheme in ['http', 'https']:
                urls.add(full_url)

        return urls
    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTRED_EX}[!] Could not crawl {url}. Error: {str(e)}")
        return set()

def crawl_and_check(url, crawl_all=False, verify_ssl=True):
    if crawl_all:
        urls_to_check = find_urls_in_page(url, verify_ssl=verify_ssl)
        urls_to_check.add(url)
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
        print(f"\n{Fore.LIGHTRED_EX}[!] URLs with missing or misconfigured security headers:")
        for insecure_url in insecure_urls:
            print(f"{Fore.LIGHTBLUE_EX}{insecure_url}")
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] All URLs have the required security headers and configurations!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crawl a website and check for missing or misconfigured security headers")
    parser.add_argument("-u", "--url", required=True, help="URL of the website to check or crawl")
    parser.add_argument("-A", "--all", action="store_true", help="Crawl all URLs in the page instead of checking just the given URL")
    parser.add_argument("-B", "--bypass", action="store_true", help="Bypass SSL certificate verification")
    parser.add_argument("-L", "--list", action="store_true", help="List all the Headers")

    args = parser.parse_args()

    if args.bypass:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.list:
        print(f"\n[*] Security Headers to Check:{Fore.RESET}")
        for header in SECURITY_HEADERS:
            print(f"  - {Fore.LIGHTGREEN_EX}{header}")
        exit()

    crawl_and_check(args.url, crawl_all=args.all, verify_ssl=not args.bypass)
