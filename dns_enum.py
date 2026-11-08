"""
DNS reconnaissance: record enumeration, reverse DNS, AXFR zone transfer testing,
and passive Certificate Transparency & dictionary subdomain discovery.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import socket
from typing import Any, Dict, List, Optional, Set

import dns.query
import dns.resolver
import dns.zone
import requests

logger = logging.getLogger("reconnoiter")

COMMON_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

DEFAULT_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "vpn",
    "remote",
    "admin",
    "portal",
    "app",
    "cloud",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "status",
    "beta",
    "shop",
    "blog",
    "m",
    "auth",
    "login",
    "sso",
]


def enumerate_dns(domain: str) -> Dict[str, List[str]]:
    """
    Queries a domain for standard DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA).
    Returns a dict mapping record_type -> list of string values.
    """
    records: Dict[str, List[str]] = {}

    for rtype in COMMON_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except Exception:
            records[rtype] = []

    return records


def reverse_dns(ip: str) -> Optional[str]:
    """
    Attempts a reverse DNS (PTR) lookup for an IP address.
    Returns the hostname string, or None if it fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def test_zone_transfer(domain: str) -> Dict[str, Any]:
    """
    Tests whether nameservers authoritative for the domain permit unauthenticated
    DNS zone transfers (AXFR), which can expose internal DNS topology.
    """
    results: Dict[str, Any] = {
        "vulnerable": False,
        "tested_nameservers": [],
        "vulnerable_nameservers": [],
        "leaked_records": [],
    }

    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        nameservers = [ns.to_text().rstrip(".") for ns in ns_answers]
    except Exception:
        return results

    results["tested_nameservers"] = nameservers

    for ns in nameservers:
        try:
            # Resolve the nameserver hostname to IP
            ns_ips = socket.getaddrinfo(ns, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for entry in ns_ips:
                ns_ip = entry[4][0]
                try:
                    # Attempt AXFR zone transfer
                    xfr = dns.query.xfr(ns_ip, domain, timeout=5, lifetime=10)
                    zone = dns.zone.from_xfr(xfr)
                    if zone:
                        results["vulnerable"] = True
                        if ns not in results["vulnerable_nameservers"]:
                            results["vulnerable_nameservers"].append(ns)
                        for name, node in zone.nodes.items():
                            record_str = f"{name}.{domain} -> {node.to_text(name)}"
                            if len(results["leaked_records"]) < 100:
                                results["leaked_records"].append(record_str)
                except Exception:
                    # AXFR refused or failed (expected secure behavior)
                    continue
        except Exception:
            continue

    return results


def _query_crtsh(domain: str) -> Set[str]:
    """
    Queries crt.sh Certificate Transparency logs over HTTPS for passive subdomain discovery.
    """
    subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "ReconScanner/1.0"}

    try:
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub.endswith(f".{domain.lower()}") or sub == domain.lower():
                        subdomains.add(sub)
    except Exception as e:
        logger.debug(f"crt.sh passive discovery error: {e}")

    return subdomains


def _resolve_subdomain(subdomain: str) -> List[str]:
    """Resolves A and AAAA records for a given subdomain."""
    ips = []
    try:
        answers = dns.resolver.resolve(subdomain, "A", lifetime=3)
        for rdata in answers:
            ips.append(rdata.to_text())
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(subdomain, "AAAA", lifetime=3)
        for rdata in answers:
            ips.append(rdata.to_text())
    except Exception:
        pass

    return ips


def enumerate_subdomains(
    domain: str,
    use_crtsh: bool = True,
    wordlist: Optional[List[str]] = None,
    max_workers: int = 15,
) -> Dict[str, List[str]]:
    """
    Discovers subdomains using passive Certificate Transparency (crt.sh)
    and active dictionary-based DNS resolution in parallel.
    Returns a dict mapping {subdomain: [ip1, ip2, ...]}.
    """
    candidate_subdomains: Set[str] = set()

    # 1. Passive Certificate Transparency lookup
    if use_crtsh:
        ct_subdomains = _query_crtsh(domain)
        candidate_subdomains.update(ct_subdomains)

    # 2. Dictionary-based candidates
    words = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
    for w in words:
        candidate_subdomains.add(f"{w.lower()}.{domain.lower()}")

    # 3. Resolve all candidate subdomains concurrently
    resolved_subdomains: Dict[str, List[str]] = {}
    if not candidate_subdomains:
        return resolved_subdomains

    with ThreadPoolExecutor(max_workers=min(len(candidate_subdomains), max_workers)) as executor:
        future_to_sub = {
            executor.submit(_resolve_subdomain, sub): sub
            for sub in candidate_subdomains
        }
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ips = future.result()
                if ips:
                    resolved_subdomains[sub] = ips
            except Exception:
                continue

    return resolved_subdomains
