"""
Protocol-aware and TLS-capable banner grabbing with concurrent execution.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
import ssl
from typing import Dict, List, Optional, Set

# Standard ports known to use TLS/SSL encryption
DEFAULT_TLS_PORTS: Set[int] = {443, 8443, 993, 995, 465, 8443, 9443, 636}

# Standard ports typically serving HTTP/HTTPS protocols
DEFAULT_HTTP_PORTS: Set[int] = {80, 8080, 8000, 8888, 3000, 5000, 8008, 9000}
DEFAULT_HTTPS_PORTS: Set[int] = {443, 8443, 9443}


def _create_ssl_context() -> ssl.SSLContext:
    """Creates a permissive SSL context for banner grabbing against self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe_http(sock: socket.socket, host_header: str) -> str:
    """
    Sends structured HTTP HEAD (with GET fallback) to elicit status code,
    Server header, and HTML <title> tag.
    """
    head_req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: ReconScanner/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(head_req.encode("utf-8", errors="ignore"))
    response = sock.recv(4096).decode("utf-8", errors="ignore")

    # If HEAD is refused, empty, or returns 405 Method Not Allowed, try GET
    if not response or "405" in response or "400 Bad Request" in response:
        try:
            get_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: ReconScanner/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(get_req.encode("utf-8", errors="ignore"))
            response = sock.recv(4096).decode("utf-8", errors="ignore")
        except Exception:
            pass

    if not response:
        return ""

    lines = [line.strip() for line in response.split("\r\n") if line.strip()]
    if not lines:
        return ""

    status_line = lines[0]
    server_header = ""
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server_header = line
            break

    # Extract HTML <title> if present
    title_str = ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
    if title_match:
        extracted = " ".join(title_match.group(1).split()).strip()
        if extracted:
            title_str = f"Title: {extracted[:45]}"

    parts = [status_line]
    if server_header:
        parts.append(server_header)
    if title_str:
        parts.append(title_str)

    return " | ".join(parts)


def _probe_generic(sock: socket.socket) -> str:
    """
    Reads an unsolicited banner (e.g. SSH, FTP, SMTP), or sends CRLF if silent.
    """
    try:
        data = sock.recv(2048)
    except socket.timeout:
        data = b""

    if not data:
        try:
            sock.sendall(b"\r\n")
            data = sock.recv(2048)
        except Exception:
            data = b""

    return data.decode("utf-8", errors="ignore").strip()


def grab_banner(
    ip: str,
    port: int,
    timeout: float = 2.0,
    hostname: Optional[str] = None,
    use_tls: Optional[bool] = None,
) -> str:
    """
    Grabs the service banner for a specific IP and port.
    Detects HTTP/HTTPS, performs TLS handshake on encrypted ports,
    and falls back gracefully across protocols.
    """
    host_header = hostname if hostname else ip
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    is_tls = use_tls if use_tls is not None else (port in DEFAULT_TLS_PORTS)
    is_http_service = (port in DEFAULT_HTTP_PORTS) or (port in DEFAULT_HTTPS_PORTS)

    try:
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        sock = raw_sock
        tls_info = ""
        if is_tls:
            try:
                ssl_ctx = _create_ssl_context()
                server_name = hostname if hostname and not hostname.replace(".", "").isdigit() else None
                sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=server_name)
                try:
                    ver = sock.version() or ""
                    cipher = sock.cipher()
                    cipher_str = cipher[0] if cipher else ""
                    if ver:
                        tls_info = f"TLS: {ver}" + (f" ({cipher_str})" if cipher_str else "")
                except Exception:
                    pass
            except Exception:
                # If TLS handshake fails on suspected TLS port, fallback to plain socket
                raw_sock.close()
                raw_sock = socket.socket(family, socket.SOCK_STREAM)
                raw_sock.settimeout(timeout)
                raw_sock.connect((ip, port))
                sock = raw_sock
                is_http_service = port in DEFAULT_HTTP_PORTS

        with sock:
            if is_http_service:
                banner = _probe_http(sock, host_header)
                if not banner:
                    banner = _probe_generic(sock)
            else:
                banner = _probe_generic(sock)
                # If server sent nothing or closed on empty CRLF, try HTTP HEAD probe
                if not banner or banner.startswith("400") or "Bad Request" in banner:
                    try:
                        banner = _probe_http(sock, host_header)
                    except Exception:
                        pass

            if tls_info and is_tls:
                banner = f"{banner} | {tls_info}" if banner else tls_info

            # Clean and truncate if excessively long
            cleaned = banner.replace("\r", " ").replace("\n", " ").strip()
            return cleaned[:300] if len(cleaned) > 300 else cleaned

    except Exception:
        return ""


def grab_banners_concurrent(
    ip: str,
    ports: List[int],
    timeout: float = 2.0,
    hostname: Optional[str] = None,
    max_workers: int = 10,
) -> Dict[int, str]:
    """
    Grabs banners concurrently across multiple open ports using ThreadPoolExecutor.
    Returns a mapping of {port: banner_text}.
    """
    results: Dict[int, str] = {}
    if not ports:
        return results

    worker_count = min(len(ports), max_workers)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_port = {
            executor.submit(grab_banner, ip, port, timeout, hostname): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results[port] = future.result()
            except Exception:
                results[port] = ""

    return results
