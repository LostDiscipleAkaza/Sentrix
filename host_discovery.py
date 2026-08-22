import subprocess
import platform


def is_host_alive(ip, timeout=2):
    """
    Checks if a host responds to ICMP ping.
    Uses the system 'ping' binary so no raw sockets / root privileges
    are required.
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except Exception:
        return False