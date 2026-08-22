import nmap

from utils import safe_get
from banner_grabber import grab_banner

scanner = nmap.PortScanner()


def scan(ip):

    scanner.scan(
        ip,
        arguments="-sV -sS -Pn -O --top-ports 200"
    )

    findings = []
    os_info = []

    if ip not in scanner.all_hosts():
        return findings, os_info

    host_data = scanner[ip]

    for match in host_data.get("osmatch", []):
        os_info.append({
            "name": match.get("name", "unknown"),
            "accuracy": match.get("accuracy", "0")
        })

    tcp = host_data.get("tcp", {})

    for port, svc in tcp.items():

        if safe_get(svc, "state") != "open":
            continue

        banner = grab_banner(ip, port)

        findings.append({

            "port": port,

            "protocol": "tcp",

            "service": safe_get(svc, "name", "unknown"),

            "product": safe_get(svc, "product", ""),

            "version": safe_get(svc, "version", ""),

            "extra_info": safe_get(svc, "extrainfo", ""),

            "cpes": safe_get(svc, "cpe", []),

            "banner": banner,

            "cves": []

        })

   
    
    return findings, os_info