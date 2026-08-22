import socket


def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            try:
                banner = s.recv(1024)
            except socket.timeout:
                banner = b""

            if not banner:
                try:
                    s.sendall(b"\r\n")
                    banner = s.recv(1024)
                except Exception:
                    banner = b""

            return banner.decode(errors="ignore").strip()
    except Exception:
        return ""