"""
Target resolution and specifier expansion (domains, IPv4, IPv6, CIDR blocks, ranges, and files).
"""

import ipaddress
import os
import socket
from typing import Dict, List, Optional, Set


def is_ip_address(val: str) -> bool:
    """Checks whether the given string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val.strip())
        return True
    except ValueError:
        return False


def resolve(target: str) -> List[str]:
    """
    Resolves a hostname to all associated IPv4 and IPv6 addresses using socket.getaddrinfo().
    If target is already an IP address, returns a list containing only that IP.
    Returns an empty list if resolution fails or input is invalid.
    """
    target = target.strip()
    if not target:
        return []

    if is_ip_address(target):
        return [target]

    resolved_ips: List[str] = []
    seen: Set[str] = set()

    try:
        # socket.AF_UNSPEC retrieves both IPv4 (AF_INET) and IPv6 (AF_INET6)
        addr_info = socket.getaddrinfo(
            target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        for entry in addr_info:
            sockaddr = entry[4]
            ip = sockaddr[0]
            if ip and ip not in seen:
                seen.add(ip)
                resolved_ips.append(ip)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []

    return resolved_ips


def expand_cidr(cidr_str: str, max_hosts: int = 1024) -> List[str]:
    """
    Expands an IPv4 or IPv6 CIDR block (e.g. '192.168.1.0/24') into host IP strings.
    For single host prefixes (/32 or /128), returns the single IP.
    Enforces a safety maximum (default: 1024 hosts) to prevent out-of-memory stalls on large subnets.
    """
    try:
        network = ipaddress.ip_network(cidr_str.strip(), strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        hosts = []
        for i, ip in enumerate(network.hosts()):
            if i >= max_hosts:
                break
            hosts.append(str(ip))
        return hosts
    except ValueError:
        return []


def expand_ip_range(range_str: str) -> List[str]:
    """
    Expands an IP range into a list of individual IP strings.
    Supported formats:
      - '192.168.1.1-192.168.1.10'
      - '192.168.1.1-10'
    """
    range_str = range_str.strip()
    if "-" not in range_str:
        return [range_str] if is_ip_address(range_str) else []

    parts = range_str.split("-")
    if len(parts) != 2:
        return []

    start_str = parts[0].strip()
    end_str = parts[1].strip()

    try:
        start_ip = ipaddress.ip_address(start_str)

        if "." in end_str or ":" in end_str:
            end_ip = ipaddress.ip_address(end_str)
        else:
            # Short format: 192.168.1.1-10
            if isinstance(start_ip, ipaddress.IPv4Address):
                octets = start_str.split(".")
                octets[-1] = end_str
                end_ip = ipaddress.ip_address(".".join(octets))
            else:
                return []

        if start_ip.version != end_ip.version or int(start_ip) > int(end_ip):
            return []

        # Bound range to a sensible maximum (e.g., 1024 hosts) to prevent accidental OOM
        max_hosts = 1024
        count = int(end_ip) - int(start_ip) + 1
        if count > max_hosts:
            count = max_hosts

        ips = [
            str(ipaddress.ip_address(int(start_ip) + i))
            for i in range(count)
        ]
        return ips
    except ValueError:
        return []


def parse_target_specifier(spec: str) -> List[str]:
    """
    Parses a single target specifier which may be:
    - CIDR notation ('192.168.1.0/24')
    - IP range ('192.168.1.1-192.168.1.10')
    - Single IP ('192.168.1.1')
    - Hostname / domain ('example.com')
    Returns a list of target items (IPs or hostnames).
    """
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        return expand_cidr(spec)

    if "-" in spec and not spec.startswith("-"):
        range_ips = expand_ip_range(spec)
        if range_ips:
            return range_ips

    return [spec]


def parse_targets_file(filepath: str) -> List[str]:
    """
    Reads a target list file (like nmap -iL).
    Skips empty lines and comments (#). Expands any CIDRs, ranges, or targets on each line.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Target list file not found: {filepath}")

    targets: List[str] = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            targets.extend(parse_target_specifier(cleaned))

    return targets


def resolve_all_targets(
    target_specs: List[str], target_file: Optional[str] = None
) -> Dict[str, List[str]]:
    """
    Consolidates target specifiers and optional target file, expanding all targets
    and resolving domains to their associated IP addresses.
    Returns:
        { target_identifier: [resolved_ip_1, resolved_ip_2, ...] }
    """
    all_targets: List[str] = []

    for spec in target_specs:
        all_targets.extend(parse_target_specifier(spec))

    if target_file:
        all_targets.extend(parse_targets_file(target_file))

    # Deduplicate while preserving order
    deduped: List[str] = []
    seen: Set[str] = set()
    for t in all_targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    results: Dict[str, List[str]] = {}
    for target in deduped:
        resolved = resolve(target)
        results[target] = resolved

    return results
