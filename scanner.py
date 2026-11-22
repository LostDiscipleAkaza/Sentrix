"""
Port and service scanner integrating nmap with socket-based fallback and concurrent banner grabbing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

from banner_grabber import grab_banners_concurrent
from fingerprint import perform_deep_http_fingerprint
from utils import safe_get

logger = logging.getLogger("sentrix")

try:
    import nmap
    _HAS_NMAP = True
except ImportError:
    nmap = None
    _HAS_NMAP = False

COMMON_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888, 27017, 5432, 6379
]


def infer_cpe_from_banner(banner: str, port: int = 0) -> Tuple[List[str], str, str]:
    """
    Infers (cpe_list, product, version) from raw service banners.
    Enables native socket scans to look up CVEs even without Nmap installed.
    """
    if not banner:
        return [], "", ""

    patterns = [
        # Apache HTTP Server: Apache/2.4.49, Apache/2.4.52 (Ubuntu)
        (r"Apache(?:/([0-9\.]+))?", "apache", "http_server", "Apache httpd"),
        # Nginx: nginx/1.18.0
        (r"nginx(?:/([0-9\.]+))?", "igor_sysoev", "nginx", "nginx"),
        # OpenSSH: SSH-2.0-OpenSSH_8.9p1
        (r"OpenSSH(?:_([0-9\.]+(?:p[0-9]+)?))?", "openbsd", "openssh", "OpenSSH"),
        # Dropbear SSH: dropbear_2020.81
        (r"dropbear(?:_([0-9\.]+))?", "dropbear_ssh_project", "dropbear_ssh", "Dropbear SSH"),
        # vsftpd: vsFTPd 3.0.3
        (r"vsFTPd(?:[\s/]([0-9\.]+))?", "vsftpd", "vsftpd", "vsftpd"),
        # ProFTPD: ProFTPD 1.3.5
        (r"ProFTPD(?:[\s/]([0-9\.]+))?", "proftpd", "proftpd", "ProFTPD"),
        # Pure-FTPd
        (r"Pure-FTPd", "pureftpd", "pure-ftpd", "Pure-FTPd"),
        # Lighttpd: lighttpd/1.4.59
        (r"lighttpd(?:/([0-9\.]+))?", "lighttpd", "lighttpd", "lighttpd"),
        # Microsoft IIS: Microsoft-IIS/10.0
        (r"Microsoft-IIS(?:/([0-9\.]+))?", "microsoft", "internet_information_services", "Microsoft IIS"),
        # MySQL: 5.7.34, 8.0.28
        (r"(?:MySQL|mysql)[-_]?([0-9\.]+)?", "oracle", "mysql", "MySQL"),
        # MariaDB: 10.3.34-MariaDB
        (r"([0-9\.]+)-MariaDB", "mariadb", "mariadb", "MariaDB"),
        # PostgreSQL: PostgreSQL 14.1
        (r"PostgreSQL(?:[\s/]([0-9\.]+))?", "postgresql", "postgresql", "PostgreSQL"),
        # Exim: Exim 4.94.2
        (r"Exim(?:[\s/]([0-9\.]+))?", "exim", "exim", "Exim"),
        # Postfix
        (r"Postfix", "postfix", "postfix", "Postfix"),
        # PHP: PHP/7.4.3
        (r"PHP/([0-9\.]+)", "php", "php", "PHP"),
        # Node.js Express
        (r"Express", "expressjs", "express", "Express"),
        # OpenSSL: OpenSSL/1.1.1f
        (r"OpenSSL/([0-9\.]+[a-z]?)", "openssl", "openssl", "OpenSSL"),
    ]

    for regex, vendor, product, display_name in patterns:
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else ""
            if version:
                cpe = f"cpe:/a:{vendor}:{product}:{version}"
            else:
                cpe = f"cpe:/a:{vendor}:{product}"
            return [cpe], display_name, version

    return [], "", ""


def _socket_probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Probes a single TCP port using a standard socket connect."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _parse_ports_list(port_spec: str) -> List[int]:
    """Parses port specification string (e.g., '80,443', '1-100', 'top-200') into port numbers."""
    if not port_spec or port_spec == "top-200":
        return COMMON_TOP_PORTS

    ports: List[int] = []
    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start_p, end_p = part.split("-")
                start = max(1, int(start_p))
                end = min(65535, int(end_p))
                if end - start > 2000:
                    end = start + 2000  # Cap socket scan range for safety
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                continue

    return list(dict.fromkeys(ports))


def socket_scan(
    ip: str, port_spec: str = "top-200", hostname: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fallback socket-based TCP port scanner when nmap is not installed or lacks privileges.
    Scans candidate ports concurrently and extracts banners.
    """
    ports_to_scan = _parse_ports_list(port_spec)
    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=min(len(ports_to_scan), 50)) as executor:
        future_to_port = {
            executor.submit(_socket_probe_port, ip, p): p for p in ports_to_scan
        }
        for future in as_completed(future_to_port):
            p = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(p)
            except Exception:
                continue

    open_ports.sort()
    findings: List[Dict[str, Any]] = []

    # Grab banners concurrently across all open ports
    banners = grab_banners_concurrent(ip, open_ports, hostname=hostname)

    for port in open_ports:
        banner = banners.get(port, "")
        svc_name = "unknown"
        if port in (80, 8080, 8000):
            svc_name = "http"
        elif port in (443, 8443):
            svc_name = "https"
        elif port == 22:
            svc_name = "ssh"
        elif port == 21:
            svc_name = "ftp"
        elif port == 25:
            svc_name = "smtp"
        elif port == 3306:
            svc_name = "mysql"
        elif port == 5432:
            svc_name = "postgresql"

        inferred_cpes, inferred_product, inferred_ver = infer_cpe_from_banner(banner, port)

        fp = {}
        if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443) or svc_name in ("http", "https"):
            fp = perform_deep_http_fingerprint(ip, port, hostname=hostname)
            if fp.get("title") and "Title:" not in banner:
                banner = f"{banner} | Title: {fp['title']}" if banner else f"Title: {fp['title']}"
            if fp.get("technologies") and not inferred_product:
                inferred_product = fp["technologies"][0]

        findings.append({
            "port": port,
            "protocol": "tcp",
            "service": svc_name,
            "product": inferred_product,
            "version": inferred_ver,
            "extra_info": "",
            "cpes": inferred_cpes,
            "banner": banner,
            "cves": [],
            "waf_cdn": fp.get("waf_cdn"),
            "technologies": fp.get("technologies", []),
            "security_headers": fp.get("security_headers", {}),
            "tls_cert": fp.get("tls_cert"),
            "title": fp.get("title", ""),
        })

    return findings, []


def scan(
    ip: str, port_spec: str = "top-200", hostname: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Performs port and service scanning.
    Uses nmap SYN scan (-sS -sV -O) if available and privileged;
    falls back smoothly to socket scanning if nmap is absent or restricted.
    Banners are retrieved concurrently for all discovered open ports.
    """
    findings: List[Dict[str, Any]] = []
    os_info: List[Dict[str, Any]] = []

    if not _HAS_NMAP or nmap is None:
        logger.debug("nmap module not installed. Falling back to native socket scanner.")
        return socket_scan(ip, port_spec, hostname)

    try:
        scanner = nmap.PortScanner()

        # Build nmap arguments based on port specification
        ipv6_flag = " -6" if ":" in ip else ""
        if port_spec == "top-200":
            nmap_args = f"-sV -sS -Pn -O --top-ports 200{ipv6_flag}"
        elif port_spec.startswith("top-"):
            count = port_spec[4:]
            nmap_args = f"-sV -sS -Pn -O --top-ports {count}{ipv6_flag}"
        else:
            nmap_args = f"-sV -sS -Pn -O -p {port_spec}{ipv6_flag}"

        scanner.scan(ip, arguments=nmap_args)

        if ip not in scanner.all_hosts():
            return findings, os_info

        host_data = scanner[ip]

        for match in host_data.get("osmatch", []):
            os_info.append({
                "name": match.get("name", "unknown"),
                "accuracy": match.get("accuracy", "0"),
            })

        tcp = host_data.get("tcp", {})
        open_ports = [
            port for port, svc in tcp.items() if safe_get(svc, "state") == "open"
        ]

        # Grab banners concurrently in parallel for all open ports
        banners = grab_banners_concurrent(ip, open_ports, hostname=hostname)

        for port in open_ports:
            svc = tcp[port]
            banner = banners.get(port, "")

            cpe_entry = safe_get(svc, "cpe", [])
            cpes = [cpe_entry] if isinstance(cpe_entry, str) else cpe_entry
            svc_name = safe_get(svc, "name", "unknown")

            fp = {}
            if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443) or "http" in svc_name:
                fp = perform_deep_http_fingerprint(ip, port, hostname=hostname)
                if fp.get("title") and "Title:" not in banner:
                    banner = f"{banner} | Title: {fp['title']}" if banner else f"Title: {fp['title']}"

            findings.append({
                "port": port,
                "protocol": "tcp",
                "service": svc_name,
                "product": safe_get(svc, "product", ""),
                "version": safe_get(svc, "version", ""),
                "extra_info": safe_get(svc, "extrainfo", ""),
                "cpes": cpes,
                "banner": banner,
                "cves": [],
                "waf_cdn": fp.get("waf_cdn"),
                "technologies": fp.get("technologies", []),
                "security_headers": fp.get("security_headers", {}),
                "tls_cert": fp.get("tls_cert"),
                "title": fp.get("title", ""),
            })

        return findings, os_info

    except Exception as e:
        logger.warning(f"nmap execution encountered an issue ({e}). Using native socket scanner.")
        return socket_scan(ip, port_spec, hostname)
