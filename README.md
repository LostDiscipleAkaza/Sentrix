\# Reconnoiter



A lightweight command-line recon and vulnerability-scanning pipeline for a single target domain. It resolves the domain, checks host liveness, enumerates DNS records, runs an `nmap` service/OS scan, cross-references discovered services against known CVEs (via NVD, with a CIRCL fallback), and writes a timestamped JSON report.



\## What it does



1\. \*\*Resolve\*\* — looks up the domain's IP address (`resolver.py`)

2\. \*\*Host check\*\* — pings the IP to confirm it's alive (`host\_discovery.py`)

3\. \*\*DNS enumeration\*\* — queries common record types (A, AAAA, MX, NS, TXT, CNAME, SOA) plus reverse DNS (`dns\_enum.py`)

4\. \*\*Port/service scan\*\* — runs an `nmap` SYN scan with service/version and OS detection on the top 200 ports, grabbing raw banners for each open port (`scanner.py`, `banner\_grabber.py`)

5\. \*\*CVE lookup\*\* — matches each detected service's CPE against the NVD CVE database, falling back to CIRCL's Vulnerability-Lookup service when NVD has no exact match or errors out (`cve\_lookup.py`)

6\. \*\*Report\*\* — writes a full JSON report to `reports/` (`report.py`)



\## Requirements



\- Python 3.8+

\- \[`nmap`](https://nmap.org/) installed and on your `PATH`

\- Root/administrator privileges (required for `nmap`'s SYN scan and OS detection)



Install Python dependencies:



```bash

pip install -r requirements.txt

```



\## Usage



```bash

sudo python3 main.py <domain>

```



Example:



```bash

sudo python3 main.py example.com

```



Output is printed to the console as the scan progresses, and a full JSON report is written to `reports/<domain>\_<timestamp>.json`.



\## Optional: NVD API key



By default, CVE lookups against NVD are rate-limited to 5 requests per 30 seconds. Setting an API key raises this to 50 requests per 30 seconds.



1\. Request a free key: https://nvd.nist.gov/developers/request-an-api-key

2\. Export it before running:



```bash

export NVD\_API\_KEY=your-key-here

```



\## Notes



\- If `nmap` can't determine a service's version, no CPE is available and CVE matching for that service is reported as `unmatched` (not silently skipped).

\- A CVE lookup that fails outright (network error, rate limit, bad response) is reported as `error`, distinct from `unmatched` ("we checked and found nothing") — this distinction is intentional so a failed check is never mistaken for a clean result.

\- This tool performs active scanning (SYN scans, port probing, banner grabbing). Only run it against hosts you own or have explicit authorization to test.



\## Project structure



```

main.py            Entry point / orchestration

resolver.py         DNS-to-IP resolution

host\_discovery.py   ICMP liveness check

dns\_enum.py          DNS record + reverse DNS enumeration

scanner.py           nmap-based port/service/OS scan

banner\_grabber.py    Raw TCP banner grabbing

cve\_lookup.py        NVD + CIRCL CVE matching

report.py            JSON report generation

utils.py             Shared helpers

requirements.txt     Python dependencies

```

