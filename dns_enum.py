import socket

import dns.resolver  # pip install dnspython


COMMON_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def enumerate_dns(domain):
    """
    Queries a domain for a set of common DNS record types.
    Returns a dict of record_type -> list of string values
    (empty list if that record type doesn't exist / query failed).
    """
    records = {}

    for rtype in COMMON_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except Exception:
            records[rtype] = []

    return records


def reverse_dns(ip):
    """
    Attempts a reverse DNS (PTR) lookup for an IP address.
    Returns the hostname string, or None if it fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None