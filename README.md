# Reconnoiter 2.0

An advanced, resilient command-line network reconnaissance and vulnerability assessment pipeline. It resolves multi-target inputs (domains, IPv4, IPv6, CIDR blocks, IP ranges, target list files), conducts firewall-resilient host liveness checks, performs DNS enumeration (with zone transfer tests and passive/dictionary subdomain discovery), executes service/port scanning with protocol-aware concurrent banner grabbing, cross-references discovered services against known CVEs with local 7-day SQLite caching, enriches findings with EPSS exploitation probabilities and CISA Known Exploited Vulnerabilities (KEV) intelligence, and generates structured reports across JSON, HTML, and Markdown formats.

---

## Capabilities & Architecture

1. **Target Flexibility & Resolution (`resolver.py`)**
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

4. **Service Scanning & Concurrent Banner Grabbing (`scanner.py`, `banner_grabber.py`)**
   - Runs `nmap` service/OS detection with automatic fallback to high-speed native socket scanning if `nmap` is unavailable or unprivileged.
   - **Protocol-Aware Probing**: Sends structured HTTP `HEAD /` requests to elicit accurate server headers.
   - **TLS/SSL Handshake Wrapping**: Automatically wraps SSL/TLS connections on ports like 443, 8443, 993.
   - **Concurrency**: Banner grabbing runs in parallel across all open ports using `concurrent.futures.ThreadPoolExecutor`.

5. **Vulnerability Intelligence & Caching (`cve_lookup.py`)**
   - **Local SQLite Cache (`cve_cache.db`)**: Caches CPE lookups with a 7-day TTL to eliminate NIST NVD rate-limit delays (5 req/30s).
   - **CISA KEV Integration**: Flags vulnerabilities actively exploited in the wild by threat actors.
   - **EPSS Integration**: Fetches Exploit Prediction Scoring System probabilities and percentiles from the FIRST API.
   - **CIRCL Fallback & Vendor Aliasing**: Automatically resolves renamed vendor CPEs and falls back to CIRCL if NVD has no exact dictionary match.

6. **Multi-Format Reporting & Remediation (`report.py`)**
   - Generates reports in **JSON**, **HTML**, and **Markdown** (`--format json,html,markdown`).
   - **Interactive HTML**: Modern dark cybersecurity interface with KPI cards, severity meter bars, CVE links, threat badges, and contextual remediation recommendations.
   - **Scan Metadata**: Records scanner version, CLI flags used, start/end timestamps, duration, and target IP details.

---

## Requirements

- Python 3.8+
- Optional: [`nmap`](https://nmap.org/) on `PATH` (Reconnoiter seamlessly falls back to native socket scanning if nmap is omitted or unprivileged)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic single target scan
python main.py example.com

# CIDR block scan across top 200 ports
python main.py 192.168.1.0/24

# Custom port range with no ping check and multi-format reports
python main.py example.com -p 1-1000 --no-ping -o report -f html,json,markdown

# Input target list from file with NVD API key and verbose logging
python main.py -iL targets.txt --api-key $NVD_API_KEY -v
```

### CLI Flags

| Flag | Description |
| :--- | :--- |
| `targets` | Target hostname(s), IP address(es), CIDR block(s), or IP range(s) |
| `-iL, --input-list` | Path to target list file (one per line, comments `#` supported) |
| `-p, --ports` | Ports to scan (`80,443`, `1-1000`, or `top-200`) [default: `top-200`] |
| `--no-ping` | Skip ICMP/TCP host liveness probe |
| `--api-key` | NVD API Key (raises rate limit from 5 to 50 req/30s) |
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
    ├── test_cve_lookup.py
    ├── test_dns_enum.py
    ├── test_report.py
    └── test_cli.py
```
