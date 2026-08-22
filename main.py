import sys

from resolver import resolve
from host_discovery import is_host_alive
from dns_enum import enumerate_dns, reverse_dns
from scanner import scan
from report import write_report
from cve_lookup import lookup_cves


def check_cves(finding):
    """
    Resolves a scanner finding's CPE (if any) and looks up CVEs.
    Mutates and returns finding with 'cve_status' and 'cves' set.
    No CPE -> "unmatched", never silently guessed via keyword search.
    """
    cpe = finding.get("cpes")
    cpe_str = (cpe[0] if isinstance(cpe, list) else cpe) if cpe else None

    if cpe_str:
        result = lookup_cves(cpe_str)
    else:
        result = {"status": "unmatched", "cves": [], "reason": "no_cpe_from_nmap"}

    finding["cve_status"] = result["status"]
    finding["cves"] = result["cves"]
    finding["cve_reason"] = result.get("reason")
    finding["cve_source"] = result.get("source")
    return finding


def print_finding(finding):
    print(
        f"Port: {finding['port']}, "
        f"Service: {finding['service']}, "
        f"Version: {finding['version']}"
    )
    if finding["banner"]:
        print(f"Banner: {finding['banner']}")

    status = finding["cve_status"]
    cves = finding["cves"]

    if status == "matched":
        top = cves[:10]
        shown = ", ".join(
            f"{c['id']} ({c['cvss'] if c['cvss'] is not None else '?'})"
            for c in top
        )
        source = finding.get("cve_source", "nvd")
        print(f"CVEs [{source}]: {len(cves)} found, top {len(top)} by CVSS -> {shown}")
        remaining = len(cves) - len(top)
        if remaining > 0:
            print(f"      ...and {remaining} more in report.json")
    elif status == "unmatched":
        print(f"CVEs: none matched ({finding.get('cve_reason', 'no match')})")
    else:
        print(
            f"CVEs: LOOKUP FAILED ({finding.get('cve_reason', 'unknown')}) "
            f"- do not treat this as a clean result"
        )

    print("-" * 60)


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <domain>")
        return

    domain = sys.argv[1]

    print(f"[*] Resolving domain: {domain}")
    ip = resolve(domain)

    if not ip:
        print(f"[-] Could not resolve domain: {domain}")
        return

    print(f"[+] Resolved IP: {ip}")

    print("[*] Checking host availability...")
    alive = is_host_alive(ip)
    status = "alive" if alive else "not responding to ping (continuing anyway)"
    print(f"[{'+' if alive else '-'}] Host is {status}")

    print(f"[*] Enumerating DNS records for {domain}...")
    dns_records = enumerate_dns(domain)
    for rtype, values in dns_records.items():
        if values:
            print(f"    {rtype}: {', '.join(values)}")

    ptr = reverse_dns(ip)
    if ptr:
        print(f"    PTR: {ptr}")

    print(f"[*] Scanning {ip}...")
    try:
        findings, os_info = scan(ip)
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        print("    (nmap SYN scan / OS detection usually require root privileges)")
        return

    if os_info:
        print("[+] OS Detection guesses:")
        for match in os_info:
            print(f"    {match['name']} ({match['accuracy']}% confidence)")

    if not findings:
        print(f"[!] No open TCP ports found on {ip}")
        write_report(domain, ip, [], dns_records, os_info, alive)
        return

    print(f"[+] Found {len(findings)} open service(s)\n")

    for finding in findings:
        print(f"[*] Checking CVEs for {finding['service']} {finding['version']}")
        check_cves(finding)
        print_finding(finding)

    write_report(domain, ip, findings, dns_records, os_info, alive)


if __name__ == "__main__":
    main()