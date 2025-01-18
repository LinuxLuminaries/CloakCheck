# CloakCheck

A Great Tool to Scan for missing or misconfigured Headers in Websites.

## Installation

Clone the repository, install the requierements.

```bash
git clone https://github.com/LinuxLuminaries/CloakCheck.git && cd CloakCheck
```

```bash
pip install -r requierements.txt
```


## Usage

```sh
$ python cloakcheck.py -u www.example.com [options]

Options:
  -h, --help            show this help message and exit
  -A, --all             Crawl all URLs in the page instead of checking just the given URL.
  -B, --bypass          Bypass SSL certificate verification
  -L, --list            List all the Security Headers to Check
```

## Output

```bash
[*] Checking security headers for the provided URL: https://www.example.com/

[!] Missing Security Headers for URL: https://www.example.com/
Missing Headers: ['Content-Security-Policy', 'Strict-Transport-Security', 'X-XSS-Protection', 'Pragma', 'Feature-Policy', 'Access-Control-Allow-Origin']

  - Issue: Missing Content-Security-Policy - Recommendation: No specific recommendation available.
  - Issue: Missing Strict-Transport-Security - Recommendation: Configure Strict-Transport-Security with a 'max-age' of at least 31536000 (1 year) and include 'includeSubDomains' to enforce security across all subdomains.
  - Issue: Missing X-XSS-Protection - Recommendation: No specific recommendation available.
  - Issue: Missing Pragma - Recommendation: Set Pragma to 'no-cache' to control caching behavior.
  - Issue: Missing Feature-Policy - Recommendation: Define a Feature-Policy to control which features can be used in the web application.
  - Issue: Missing Access-Control-Allow-Origin - Recommendation: Configure Access-Control-Allow-Origin to restrict which domains can access resources.

[!] URLs with missing or misconfigured security headers:
https://example.com
```
## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

