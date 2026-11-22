```text
  ____             _        _      
 / ___|  ___ _ __ | |_ _ __(_)_  __
 \___ \ / _ \ '_ \| __| '__| \ \/ /
  ___) |  __/ | | | |_| |  | |>  < 
 |____/ \___|_| |_|\__|_|  |_/_/\_\
```

# Sentrix 2.1

An advanced, resilient command-line network reconnaissance and threat assessment pipeline. Sentrix supports dual input modes (command line arguments and interactive prompt), resolves multi-target inputs (domains, IPv4, IPv6, CIDR blocks, IP ranges, target list files), conducts firewall-resilient host liveness checks, performs DNS enumeration (with zone transfer tests and passive/dictionary subdomain discovery), queries Shodan InternetDB for historical port & vuln intel, executes service/port scanning with protocol-aware concurrent banner grabbing, performs deep web technology & OWASP security header auditing, cross-references discovered services against known CVEs with local 7-day SQLite caching, enriches findings with EPSS exploitation probabilities and CISA Known Exploited Vulnerabilities (KEV) intelligence, and generates structured reports across JSON, HTML, and Markdown formats.

---

## Capabilities & Architecture

1. **Dual Input Modes & Target Resolution (`resolver.py`, `main.py`)**
   - **Interactive Prompt**: Run `python main.py` without arguments to launch an interactive session that prompts for target domains, IPs, or CIDR blocks.
   - **CLI Mode**: Pass targets directly via command-line arguments: `python main.py <target>`.
   - Supports hostnames, IPv4, IPv6, CIDR blocks (`192.168.1.0/24`), IP ranges (`192.168.1.1-10`), and target list files (`-iL targets.txt`).
   - Resolves all associated IPv4 and IPv6 records via `socket.getaddrinfo()`.

2. **Firewall-Resilient Host Discovery (`host_discovery.py`)**
   - Combines ICMP echo ping with unprivileged TCP Connect ping probes against common ports (80, 443, 22).
   - If modern firewalls or cloud security groups drop ICMP, TCP responses accurately confirm host liveness.
   - Host liveness checks can also be bypassed via `--no-ping`.

3. **DNS Reconnaissance & Subdomain Discovery (`dns_enum.py`)**
   - Common record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) and reverse DNS (PTR).
   - **DNS Zone Transfer Test (AXFR)**: Tests authoritative nameservers for unauthenticated AXFR leaks.
   - **Subdomain Enumeration**: Combines passive Certificate Transparency log queries (`crt.sh`) with concurrent dictionary resolution.

4. **Shodan InternetDB Threat Intelligence (`cve_lookup.py`)**
   - Integrates with the free Shodan InternetDB API (`https://internetdb.shodan.io/{ip}`).
   - Automatically harvests known open ports, hostnames, cloud tags (e.g. `eol-product`, `cloud`), and verified historical CVEs.
   - Caches responses locally in SQLite (`cve_cache.db`) with a 7-day TTL.

5. **Service Scanning & Concurrent Banner Grabbing (`scanner.py`, `banner_grabber.py`)**
   - Runs `nmap` service/OS detection with automatic fallback to high-speed native socket scanning if `nmap` is unavailable or unprivileged.
   - **Protocol-Aware Probing**: Sends structured HTTP `HEAD /` requests to elicit accurate server headers.
   - **TLS/SSL Handshake Wrapping**: Automatically wraps SSL/TLS connections on ports like 443, 8443, 993.
   - **Concurrency**: Banner grabbing runs in parallel across all open ports using `concurrent.futures.ThreadPoolExecutor`.

6. **Deep Detection & Fingerprinting (`fingerprint.py`)**
   - **WAF / CDN Detection**: Identifies reverse proxies and firewalls (Cloudflare, AWS CloudFront, Akamai, Fastly, Imperva, Azure Front Door, Sucuri, F5 BIG-IP) from headers and cookie heuristics.
   - **Web Stack & Framework Fingerprinting**: Inspects headers, session cookies, and DOM footprints to discover CMSs (WordPress, Drupal, Joomla), frontend frameworks (React, Next.js, Vue, Angular), and backend runtimes (PHP, Java, Django, Express, Laravel, ASP.NET).
   - **OWASP Security Headers Audit**: Evaluates critical defensive headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) with automated grading (A to F) and step-by-step remediation snippets.
   - **Deep TLS/SSL Inspection**: Extracts Subject Common Names, Subject Alternative Names (SANs - automatically recycled into subdomain intelligence), Issuer CAs, expiration timelines, and detects self-signed/untrusted certificates.

7. **Resilient Vulnerability Intelligence & Caching (`cve_lookup.py`)**
   - **Multi-Source Threat Intel**: Integrates NIST NVD API 2.0 (`--nvd-key`), CIRCL Vulnerability Lookup (`--circl-key`), and Shodan InternetDB (`--shodan-key`).
   - **Exponential Backoff & 35s Timeout**: Automatically retries on 429 rate limits or transient network errors up to 2 times before falling back.
   - **Stale Cache Fallback**: When `--no-cache` is used and a live API call fails, Sentrix falls back to previously cached records with a `(stale, from cache)` label rather than returning an unassessed failure.
   - **CISA KEV Integration**: Flags vulnerabilities actively exploited in the wild by threat actors.
   - **EPSS Integration**: Fetches Exploit Prediction Scoring System probabilities and percentiles from the FIRST API.
   - **Granular Summary States**: Summary cards explicitly reflect the worst-case assessment outcome:
     - `0 CVEs (no CPE match)`
     - `0 CVEs (lookup failed — N/N services unassessed)`
     - `0 CVEs (confirmed clean)`
     - Never collapses "failed" lookups into "clean".

8. **Multi-Format Reporting & Remediation (`report.py`)**
   - Generates reports in **JSON**, **HTML**, and **Markdown** (`--format json,html,markdown`).
   - **Interactive HTML**: Modern dark cybersecurity interface with KPI cards, severity meter bars, CVE links, threat badges, fingerprinting summary cards, and contextual remediation recommendations.
   - **Scan Metadata**: Records scanner version, CLI flags used, start/end timestamps, duration, and target IP details.

---

## Requirements

- Python 3.8+
- Optional: [`nmap`](https://nmap.org/) on `PATH` (Sentrix seamlessly falls back to native socket scanning if nmap is omitted or unprivileged)

Install dependencies:
```bash
pip install -r requirements.txt
```

### Environment Configuration (.env)

Sentrix automatically loads credentials from a local `.env` file upon startup. Copy the provided template to get started:
```bash
cp .env.example .env
```
Inside `.env`, you can configure:
- `NVD_API_KEY`: Free NIST NVD key (raises rate limit from 5 to 50 req/30s).
- `CIRCL_API_KEY`: Optional key (public API at `vulnerability.circl.lu` is free and needs no key).
- `SHODAN_API_KEY`: Optional key (`internetdb.shodan.io` is 100% free and needs no key).
- `SENTRIX_CACHE_DB`: Custom path for the SQLite threat intelligence cache (default: `cve_cache.db`).

---

## Usage

```bash
# Interactive mode (launches prompt)
python main.py

# Basic single target scan
python main.py example.com

# CIDR block scan across top 200 ports
python main.py 192.168.1.0/24

# Custom port range with no ping check and multi-format reports
python main.py example.com -p 1-1000 --no-ping -o report -f html,json,markdown

# Scan with NVD, CIRCL, and Shodan API keys with verbose logging
python main.py example.com --nvd-key $NVD_API_KEY --circl-key $CIRCL_API_KEY -v
```

### CLI Flags

| Flag | Description |
| :--- | :--- |
| `targets` | Target hostname(s), IP address(es), CIDR block(s), or IP range(s) |
| `-iL, --input-list` | Path to target list file (one per line, comments `#` supported) |
| `-p, --ports` | Ports to scan (`80,443`, `1-1000`, or `top-200`) [default: `top-200`] |
| `--no-ping` | Skip ICMP/TCP host liveness probe |
| `--nvd-key, --api-key` | NVD API Key (raises rate limit from 5 to 50 req/30s) |
| `--circl-key` | CIRCL Vulnerability Lookup API Key (`vulnerability.circl.lu`) |
| `--shodan-key` | Shodan API Key (optional for Shodan queries) |
| `--no-cache` | Bypass local SQLite cache to query fresh intelligence (with stale fallback on error) |
| `-o, --output` | Custom output report file or prefix path |
| `-f, --format` | Report formats: `json,html,markdown` (comma-separated, default: `json,html`) |
| `-v, --verbose` | Enable verbose debug output |
| `--no-subdomains` | Skip Certificate Transparency and dictionary subdomain enumeration |
| `--no-axfr` | Skip DNS zone transfer test |
| `--no-cve` | Skip CVE vulnerability matching |
| `--threads` | Concurrency worker threads [default: 10] |

---

## Testing

Run the full automated unit test suite:
```bash
python -m unittest discover tests
```

---

## Project Structure

```
├── main.py            # CLI entry point, argument parsing & workflow orchestration
├── resolver.py        # Target parsing, CIDRs, ranges, files, IPv4/IPv6 resolution
├── host_discovery.py  # Hybrid ICMP and TCP Connect ping liveness probes
├── dns_enum.py        # DNS records, reverse DNS, AXFR test, crt.sh & dictionary subdomains
├── scanner.py         # Port & service scanner (nmap + native socket fallback)
├── banner_grabber.py  # Protocol-aware HTTP/TLS banner grabbing with concurrency
├── fingerprint.py     # Deep WAF/CDN detection, web stack heuristics, OWASP headers, TLS cert
├── cve_lookup.py      # SQLite cached CVE lookups, NVD v2.0, CIRCL, CISA KEV & EPSS
├── report.py          # Multi-format report generation (JSON, HTML, Markdown)
├── utils.py           # ANSI colored logging, terminal banners, table rendering
├── pyproject.toml     # Packaging & dependencies configuration
├── requirements.txt   # Runtime dependencies
├── .gitignore         # Build, report, and cache exclusions
└── tests/             # Comprehensive unit test suite
    ├── test_resolver.py
    ├── test_host_discovery.py
    ├── test_banner_grabber.py
    ├── test_scanner.py
    ├── test_fingerprint.py
    ├── test_cve_lookup.py
    ├── test_dns_enum.py
    ├── test_report.py
    └── test_cli.py
```

---

## Authorized & Legal Testing Targets

> [!IMPORTANT]
> Always obtain explicit authorization before scanning networks or hosts you do not own. For safe, legal, and non-disruptive testing, use targets specifically authorized for security scanning:

1. **Localhost & Loopback Environments (Recommended)**
   - Target: `127.0.0.1` or `::1`
   - Test locally against mock servers, local web apps, or Dockerized testbeds:
     - OWASP Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`)
     - Damn Vulnerable Web Application (DVWA)
     - Metasploitable3 / VulnHub virtual machines

2. **Official Scanner Testing Endpoints**
   - **`scanme.nmap.org`**: Maintained by Gordon Lyon (Fyodor) and the Nmap Project specifically for testing port scanners. Scan sparingly (do not flood or DoS).
   - **`testphp.vulnweb.com`**: Provided by Invicti (Acunetix) as a deliberately vulnerable web testbed for web security tools and scanners.
   - **`httpbin.org`**: Public HTTP request/response testing endpoint suitable for banner and header inspection.
   - **`example.com` / `example.org`**: IANA-reserved special-use domains intended for documentation and non-intrusive DNS resolution checks.
