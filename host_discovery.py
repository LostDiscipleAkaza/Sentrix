"""
Host discovery combining ICMP echo with TCP connect ping probes for firewall resilience.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import socket
import subprocess
from typing import List, Optional


def icmp_ping(ip: str, timeout: float = 2.0) -> bool:
    """
    Checks if a host responds to ICMP echo using system ping.
    No raw socket / root privileges required.
    """
    system = platform.system().lower()
    is_ipv6 = ":" in ip

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000))]
        if is_ipv6:
            cmd.append("-6")
        cmd.append(ip)
    else:
        ping_bin = "ping6" if (is_ipv6 and system != "darwin") else "ping"
        cmd = [ping_bin, "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_ping(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Performs an unprivileged TCP Connect probe against a specific port.
    Returns True if the connection succeeds (SYN-ACK / 0 returncode),
    proving the host is alive even when ICMP is dropped by firewalls.
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            ret = sock.connect_ex((ip, port))
            # 0 = connection established (port open)
            return ret == 0
    except Exception:
        return False


def tcp_ping_multi(ip: str, ports: List[int], timeout: float = 1.0) -> bool:
    """
    Probes multiple TCP ports concurrently. Returns True as soon as any port connects.
    """
    if not ports:
        return False

    with ThreadPoolExecutor(max_workers=min(len(ports), 10)) as executor:
        futures = [executor.submit(tcp_ping, ip, p, timeout) for p in ports]
        for future in as_completed(futures):
            try:
                if future.result():
                    return True
            except Exception:
                continue

    return False


def is_host_alive(
    ip: str, timeout: float = 2.0, tcp_ports: Optional[List[int]] = None
) -> bool:
    """
    Hybrid liveness probe: Combines ICMP echo ping with TCP Connect ping probes.
    Modern firewalls (AWS Security Groups, Cloudflare, Windows Firewall) frequently
    drop ICMP by default. If ICMP fails, common service ports (80, 443, 22) are probed.
    """
    # 1. First probe: ICMP Echo
    if icmp_ping(ip, timeout=timeout):
        return True

    # 2. Fallback probe: TCP Connect against common ports
    candidate_ports = tcp_ports if tcp_ports is not None else [80, 443, 22]
    return tcp_ping_multi(ip, candidate_ports, timeout=min(timeout, 1.5))
