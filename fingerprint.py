"""
Deep detection, web technology fingerprinting, WAF/CDN detection,
defensive security headers auditing, and TLS certificate deep inspection.
"""

from datetime import datetime, timezone
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("reconnoiter")


# ---------------------------------------------------------------------------
# WAF & CDN Detection Signatures
# ---------------------------------------------------------------------------

WAF_SIGNATURES = [
    ("Cloudflare", [
        (re.compile(r"cloudflare", re.I), "server"),
        (re.compile(r"^cf-ray$", re.I), "headers"),
        (re.compile(r"^cf-cache-status$", re.I), "headers"),
    ]),
    ("AWS CloudFront", [
        (re.compile(r"cloudfront", re.I), "via"),
        (re.compile(r"^x-amz-cf-id$", re.I), "headers"),
        (re.compile(r"^x-amz-cf-pop$", re.I), "headers"),
    ]),
    ("Akamai", [
        (re.compile(r"akamaighost", re.I), "server"),
        (re.compile(r"^x-akamai", re.I), "headers"),
    ]),
    ("Fastly", [
        (re.compile(r"^x-fastly-request-id$", re.I), "headers"),
        (re.compile(r"^x-served-by$", re.I), "headers"),
    ]),
    ("Imperva / Incapsula", [
        (re.compile(r"^x-iinfo$", re.I), "headers"),
        (re.compile(r"^x-cdn$", re.I), "headers"),
        (re.compile(r"incapsula", re.I), "headers"),
    ]),
    ("Azure Front Door", [
        (re.compile(r"^x-azure-ref$", re.I), "headers"),
        (re.compile(r"^x-ms-request-id$", re.I), "headers"),
    ]),
    ("Sucuri", [
        (re.compile(r"^x-sucuri-id$", re.I), "headers"),
        (re.compile(r"sucuri", re.I), "server"),
    ]),
    ("F5 BIG-IP", [
        (re.compile(r"big-ip|bigip", re.I), "server"),
        (re.compile(r"bigipserver", re.I), "set-cookie"),
    ]),
]


def detect_waf_cdn(headers: Dict[str, str]) -> Optional[str]:
    """
    Detects if the target is reverse-proxied or protected by a known WAF or CDN.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for waf_name, rules in WAF_SIGNATURES:
        for pattern, check_type in rules:
            if check_type == "headers":
                if any(pattern.search(k) for k in headers_lower):
                    return waf_name
            elif check_type in headers_lower:
                val = headers_lower.get(check_type, "")
                if pattern.search(val):
                    return waf_name

    return None


# ---------------------------------------------------------------------------
# Web Technology & Framework Fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_web_technologies(headers: Dict[str, str], body: str = "") -> List[str]:
    """
    Identifies web frameworks, CMSs, programming languages, and JS libraries
    from HTTP response headers, cookies, and HTML DOM patterns.
    """
    technologies: Set[str] = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # 1. Inspect Server header
    server = headers_lower.get("server", "")
    if server:
        for s in ("nginx", "apache", "caddy", "litespeed", "gunicorn", "uwsgi", "kestrel", "envoy", "microsoft-iis"):
            if s in server.lower():
                technologies.add(server.split()[0].replace("/", " "))

    # 2. Inspect X-Powered-By
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        technologies.add(powered_by)

    # 3. Inspect Cookies
    cookie = headers_lower.get("set-cookie", "")
    if cookie:
        if "phpsessid" in cookie.lower():
            technologies.add("PHP")
        if "jsessionid" in cookie.lower():
            technologies.add("Java (JSP / Servlet)")
        if "aspsessionid" in cookie.lower() or "asp.net" in cookie.lower():
            technologies.add("ASP.NET")
        if "csrftoken" in cookie.lower() or "django" in cookie.lower():
            technologies.add("Django")
        if "connect.sid" in cookie.lower():
            technologies.add("Node.js (Express Session)")
        if "laravel_session" in cookie.lower():
            technologies.add("Laravel (PHP)")

    # 4. Inspect HTML Body Patterns (if available)
    if body:
        if "wp-content" in body or "wp-includes" in body:
            technologies.add("WordPress CMS")
        if "sites/default/files" in body or "drupal" in body.lower():
            technologies.add("Drupal CMS")
        if "joomla!" in body.lower():
            technologies.add("Joomla CMS")
        if "__NEXT_DATA__" in body or "/_next/static/" in body:
            technologies.add("Next.js (React)")
        elif "data-reactroot" in body or "__reactFiber" in body:
            technologies.add("React")
        if "data-v-" in body or "__vue__" in body:
            technologies.add("Vue.js")
        if "ng-version" in body or "ng-app" in body:
            technologies.add("Angular")
        if "bootstrap.min.css" in body or "bootstrap.bundle" in body:
            technologies.add("Bootstrap CSS")
        if "jquery.min.js" in body or "jquery-" in body:
            technologies.add("jQuery")

    return sorted(list(technologies))


# ---------------------------------------------------------------------------
# Defensive Security Headers Audit
# ---------------------------------------------------------------------------

RECOMMENDED_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Enforces HTTPS connections and guards against SSL stripping attacks.",
        "remediation": "Configure HSTS with: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "description": "Restricts sources of executable scripts, preventing Cross-Site Scripting (XSS).",
        "remediation": "Define a restrictive CSP restricting script-src, object-src, and default-src.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents site from being embedded in iframes, stopping Clickjacking attacks.",
        "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing by browsers.",
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls how much referrer information is included with requests.",
        "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Restricts browser feature usage (camera, microphone, geolocation).",
        "remediation": "Define Permissions-Policy restricting sensitive browser features.",
    },
}


def audit_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Audits the presence and strength of OWASP recommended defensive security headers.
    Returns compliance score, present headers, and missing headers with remediation guidance.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    present: Dict[str, str] = {}
    missing: List[Dict[str, str]] = []

    for header_key, meta in RECOMMENDED_HEADERS.items():
        if header_key in headers_lower:
            present[meta["name"]] = headers_lower[header_key]
        else:
            missing.append({
                "header": meta["name"],
                "description": meta["description"],
                "remediation": meta["remediation"],
            })

    total = len(RECOMMENDED_HEADERS)
    count_present = len(present)
    grade = "A" if count_present >= 5 else "B" if count_present >= 3 else "C" if count_present >= 2 else "F"

    return {
        "score": f"{count_present}/{total}",
        "grade": grade,
        "present": present,
        "missing": missing,
    }


# ---------------------------------------------------------------------------
# Deep TLS/SSL Certificate Inspection
# ---------------------------------------------------------------------------

def inspect_tls_certificate(
    ip: str, port: int, hostname: Optional[str] = None, timeout: float = 3.0
) -> Optional[Dict[str, Any]]:
    """
    Performs deep SSL/TLS handshake inspection to extract Subject Common Name,
    Subject Alternative Names (SANs), Certificate Authority Issuer, Expiry dates,
    and self-signed certificate status.
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    server_name = hostname if hostname and not hostname.replace(".", "").isdigit() else None

    # Step 1: Attempt standard verified handshake first
    ctx_verify = ssl.create_default_context()
    ctx_permissive = ssl.create_default_context()
    ctx_permissive.check_hostname = False
    ctx_permissive.verify_mode = ssl.CERT_NONE

    cert_dict: Optional[Dict[str, Any]] = None
    is_self_signed = False
    tls_version = ""
    cipher_name = ""

    # Try permissive first to ensure connection succeeds regardless of CA status
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((ip, port))
            with ctx_permissive.wrap_socket(raw_sock, server_hostname=server_name) as ssock:
                tls_version = ssock.version() or "TLS"
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else ""
                # Get raw binary DER
                der_cert = ssock.getpeercert(binary_form=True)
    except Exception as e:
        logger.debug(f"TLS inspection connection error on {ip}:{port}: {e}")
        return None

    if not der_cert:
        return None

    # Decode certificate using ssl module
    try:
        # Check if verified handshake passes
        try:
            with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
                raw_sock.settimeout(timeout)
                raw_sock.connect((ip, port))
                with ctx_verify.wrap_socket(raw_sock, server_hostname=server_name) as ssock:
                    cert_dict = ssock.getpeercert()
        except ssl.SSLCertVerificationError:
            is_self_signed = True
        except Exception:
            pass

        # If cert_dict was not populated by verified check, parse the DER
        if not cert_dict:
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            # Use ssl._ssl._test_decode_cert if available
            if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                import tempfile
                import os
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as tf:
                    tf.write(pem_cert)
                    temp_pem = tf.name
                try:
                    cert_dict = ssl._ssl._test_decode_cert(temp_pem)
                finally:
                    if os.path.exists(temp_pem):
                        os.remove(temp_pem)

    except Exception as e:
        logger.debug(f"Could not parse TLS certificate on {ip}:{port}: {e}")
        cert_dict = {}

    if not cert_dict:
        return {
            "tls_version": tls_version,
            "cipher": cipher_name,
            "subject_cn": hostname or ip,
            "sans": [],
            "issuer": "Unknown",
            "is_self_signed": is_self_signed,
            "days_until_expiry": None,
            "is_expired": False,
        }

    # Extract Subject Common Name
    subject_cn = ""
    for sub in cert_dict.get("subject", ()):
        for key, val in sub:
            if key == "commonName":
                subject_cn = val
                break

    # Extract Subject Alternative Names (SANs)
    sans: List[str] = []
    for san_type, san_val in cert_dict.get("subjectAltName", ()):
        if san_type.lower() == "dns" and san_val not in sans:
            sans.append(san_val)

    # Extract Issuer Organization
    issuer_org = ""
    for iss in cert_dict.get("issuer", ()):
        for key, val in iss:
            if key in ("organizationName", "commonName"):
                issuer_org = val
                break

    # Expiry calculation
    not_after_str = cert_dict.get("notAfter", "")
    days_left: Optional[int] = None
    is_expired = False
    if not_after_str:
        try:
            # Format: 'Jul  5 23:59:59 2027 GMT'
            expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            delta = expiry_dt - now_dt
            days_left = delta.days
            is_expired = days_left < 0
        except Exception:
            pass

    return {
        "tls_version": tls_version,
        "cipher": cipher_name,
        "subject_cn": subject_cn or hostname or ip,
        "sans": sans,
        "issuer": issuer_org or "Self-signed / Untrusted CA",
        "is_self_signed": is_self_signed or (issuer_org == subject_cn and bool(issuer_org)),
        "not_after": not_after_str,
        "days_until_expiry": days_left,
        "is_expired": is_expired,
    }


# ---------------------------------------------------------------------------
# High-Level Deep HTTP/HTTPS Fingerprinter
# ---------------------------------------------------------------------------

def perform_deep_http_fingerprint(
    ip: str, port: int, hostname: Optional[str] = None, timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Executes deep protocol and stack fingerprinting for an HTTP/HTTPS port:
    - Status code & Title
    - WAF / CDN detection
    - Web technology identification
    - Defensive security headers audit
    - TLS certificate deep inspection (if HTTPS/TLS)
    """
    is_https = port in (443, 8443, 9443)
    host_header = hostname if hostname else ip
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    response_text = ""
    headers: Dict[str, str] = {}
    status_line = ""
    html_title = ""

    raw_sock: Optional[socket.socket] = None
    try:
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        sock = raw_sock
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server_name = hostname if hostname and not hostname.replace(".", "").isdigit() else None
            sock = ctx.wrap_socket(raw_sock, server_hostname=server_name)

        with sock:
            # Send GET request with standard headers to inspect full response
            get_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: ReconScanner/2.0 (Security Audit)\r\n"
                f"Accept: text/html,application/xhtml+xml,*/*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(get_req.encode("utf-8", errors="ignore"))

            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) > 65536:
                        break  # Limit read size to 64KB
                except Exception:
                    break

            raw_bytes = b"".join(chunks)
            response_text = raw_bytes.decode("utf-8", errors="ignore")

    except Exception as e:
        logger.debug(f"Deep HTTP probe error on {ip}:{port}: {e}")
    finally:
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    # Parse headers and body
    body = ""
    if response_text:
        parts = response_text.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        if lines:
            status_line = lines[0].strip()
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

        # Extract Title
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            html_title = " ".join(title_match.group(1).split()).strip()[:60]

    # Deep analyses
    waf_cdn = detect_waf_cdn(headers) if headers else None
    technologies = fingerprint_web_technologies(headers, body)
    security_headers = audit_security_headers(headers) if headers else {}
    tls_cert = inspect_tls_certificate(ip, port, hostname=hostname, timeout=timeout) if is_https else None

    return {
        "status_line": status_line,
        "title": html_title,
        "headers": headers,
        "waf_cdn": waf_cdn,
        "technologies": technologies,
        "security_headers": security_headers,
        "tls_cert": tls_cert,
    }
