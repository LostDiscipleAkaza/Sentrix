"""
Port and service scanner integrating nmap with socket-based fallback and concurrent banner grabbing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import socket
from typing import Any, Dict, List, Optional, Tuple

from banner_grabber import grab_banners_concurrent
from utils import safe_get

logger = logging.getLogger("reconnoiter")

try:
    import nmap
    _HAS_NMAP = True
except ImportError:
    _HAS_NMAP = False

COMMON_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888, 27017, 5432, 6379
]


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

        findings.append({
            "port": port,
            "protocol": "tcp",
            "service": svc_name,
            "product": "",
            "version": "",
            "extra_info": "",
            "cpes": [],
            "banner": banner,
            "cves": [],
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

    if not _HAS_NMAP:
        logger.debug("nmap module not installed. Falling back to native socket scanner.")
        return socket_scan(ip, port_spec, hostname)

    try:
        scanner = nmap.PortScanner()

        # Build nmap arguments based on port specification
        if port_spec == "top-200":
            nmap_args = "-sV -sS -Pn -O --top-ports 200"
        elif port_spec.startswith("top-"):
            count = port_spec[4:]
            nmap_args = f"-sV -sS -Pn -O --top-ports {count}"
        else:
            nmap_args = f"-sV -sS -Pn -O -p {port_spec}"

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

            findings.append({
                "port": port,
                "protocol": "tcp",
                "service": safe_get(svc, "name", "unknown"),
                "product": safe_get(svc, "product", ""),
                "version": safe_get(svc, "version", ""),
                "extra_info": safe_get(svc, "extrainfo", ""),
                "cpes": cpes,
                "banner": banner,
                "cves": [],
            })

        return findings, os_info

    except Exception as e:
        logger.warning(f"nmap execution encountered an issue ({e}). Using native socket scanner.")
        return socket_scan(ip, port_spec, hostname)
