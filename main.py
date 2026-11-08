"""
Reconnoiter - Advanced Network Reconnaissance & Vulnerability Pipeline
"""

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional

import cve_lookup
from cve_lookup import lookup_cves
from dns_enum import enumerate_dns, enumerate_subdomains, reverse_dns, test_zone_transfer
from host_discovery import is_host_alive
from report import write_report
from resolver import is_ip_address, resolve_all_targets
from scanner import scan
from utils import ColorCodes, current_timestamp, format_table, print_banner, setup_logging


def check_cves(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolves a scanner finding's CPE (if any) and looks up CVEs.
    Enriches with EPSS probabilities and CISA Known Exploited Vulnerability status.
    """
    cpe = finding.get("cpes")
    cpe_str = (cpe[0] if isinstance(cpe, list) and cpe else cpe) if cpe else None

    if cpe_str:
        result = lookup_cves(cpe_str)
    else:
        result = {"status": "unmatched", "cves": [], "reason": "no_cpe_from_nmap"}

    finding["cve_status"] = result.get("status")
    finding["cves"] = result.get("cves", [])
    finding["cve_reason"] = result.get("reason")
    finding["cve_source"] = result.get("source")
    return finding


def print_finding(finding: Dict[str, Any]) -> None:
    """Prints a styled terminal summary for a single service finding."""
    port_str = f"{ColorCodes.BOLD}{finding['port']}/{finding.get('protocol', 'tcp')}{ColorCodes.RESET}"
    svc_str = f"{ColorCodes.CYAN}{finding['service']}{ColorCodes.RESET}"
    ver_str = f"{finding.get('version', '')}"
    prod_str = f"{finding.get('product', '')}"
    info = f" {prod_str} {ver_str}".strip()

    print(f"  {ColorCodes.GREEN}[*]{ColorCodes.RESET} Port: {port_str} | Service: {svc_str} {info}")
    if finding.get("banner"):
        print(f"      Banner: {ColorCodes.DIM}{finding['banner'][:120]}{ColorCodes.RESET}")

    status = finding.get("cve_status")
    cves = finding.get("cves", [])

    if status == "matched":
        top = cves[:8]
        shown_items = []
        for c in top:
            cid = c.get("id")
            cvss = c.get("cvss")
            score_str = str(cvss) if cvss is not None else "?"
            badges = []
            if c.get("cisa_kev"):
                badges.append(f"{ColorCodes.BOLD}{ColorCodes.RED}KEV{ColorCodes.RESET}")
            if c.get("epss") is not None and c.get("epss") >= 0.10:
                badges.append(f"{ColorCodes.YELLOW}EPSS:{(c['epss']*100):.0f}%{ColorCodes.RESET}")

            badge_str = f" [{' '.join(badges)}]" if badges else ""
            shown_items.append(f"{cid} ({score_str}){badge_str}")

        source = finding.get("cve_source", "nvd")
        print(f"      {ColorCodes.RED}[!] CVEs [{source}]:{ColorCodes.RESET} {len(cves)} found -> {', '.join(shown_items)}")
        if len(cves) > len(top):
            print(f"          {ColorCodes.DIM}...and {len(cves) - len(top)} more recorded in report{ColorCodes.RESET}")
    elif status == "unmatched":
        print(f"      {ColorCodes.DIM}CVEs: none matched ({finding.get('cve_reason', 'no match')}){ColorCodes.RESET}")
    else:
        print(f"      {ColorCodes.YELLOW}[?] CVEs: Lookup issue ({finding.get('cve_reason', 'unknown')}){ColorCodes.RESET}")

    print("  " + "-" * 60)


def build_arg_parser() -> argparse.ArgumentParser:
    """Builds and returns the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconnoiter",
        description="Reconnoiter: Advanced Network Reconnaissance & Vulnerability Assessment Pipeline",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target hostname(s), IP address(es), CIDR subnet(s) (e.g. 192.168.1.0/24), or ranges (e.g. 192.168.1.1-10)",
    )
    parser.add_argument(
        "-iL",
        "--input-list",
        dest="input_file",
        help="Path to file containing list of targets (one per line, comments with # supported)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="top-200",
        help="Ports to scan (e.g. '80,443', '1-1000', or 'top-200') [default: top-200]",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Skip host liveness check (assume hosts are up)",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help="NVD API key (raises rate limit from 5 to 50 requests/30s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        help="Custom output report file or prefix path",
    )
    parser.add_argument(
        "-f",
        "--format",
        default="json,html",
        help="Report formats: json, html, markdown (comma-separated, default: json,html)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging",
    )
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Skip Certificate Transparency and dictionary subdomain enumeration",
    )
    parser.add_argument(
        "--no-axfr",
        action="store_true",
        help="Skip DNS zone transfer (AXFR) test",
    )
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE vulnerability matching",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Concurrency worker threads [default: 10]",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.targets and not args.input_file:
        parser.print_help()
        sys.exit(1)

    logger = setup_logging(verbose=args.verbose)
    print_banner()

    if args.api_key:
        os.environ["NVD_API_KEY"] = args.api_key
        cve_lookup.API_KEY = args.api_key
        cve_lookup._MIN_INTERVAL = 0.7

    scan_start_timestamp = current_timestamp()
    start_monotonic = time.time()

    # 1. Expand and resolve all target specifications
    logger.info("Resolving target specifications...")
    try:
        resolved_map = resolve_all_targets(args.targets, args.input_file)
    except Exception as e:
        logger.error(f"Failed to process targets: {e}")
        sys.exit(1)

    if not resolved_map:
        logger.error("No valid targets identified.")
        sys.exit(1)

    logger.info(f"Loaded {len(resolved_map)} target(s) for assessment.")

    for target, resolved_ips in resolved_map.items():
        print(f"\n{ColorCodes.BOLD}{ColorCodes.CYAN}══════════════════════════════════════════════════════════════════{ColorCodes.RESET}")
        print(f" {ColorCodes.BOLD}Target:{ColorCodes.RESET} {target} | {ColorCodes.BOLD}Resolved IP(s):{ColorCodes.RESET} {', '.join(resolved_ips) if resolved_ips else 'Unresolved'}")
        print(f"{ColorCodes.BOLD}{ColorCodes.CYAN}══════════════════════════════════════════════════════════════════{ColorCodes.RESET}\n")

        is_domain = not is_ip_address(target)
        dns_records: Dict[str, List[str]] = {}
        subdomains: Dict[str, List[str]] = {}
        zone_transfer: Dict[str, Any] = {}

        # 2. DNS Reconnaissance (for domain targets)
        if is_domain:
            logger.info(f"Enumerating DNS records for {target}...")
            dns_records = enumerate_dns(target)
            for rtype, vals in dns_records.items():
                if vals:
                    print(f"  {ColorCodes.DIM}[DNS]{ColorCodes.RESET} {rtype}: {', '.join(vals)}")

            if not args.no_axfr:
                logger.info(f"Testing DNS zone transfer (AXFR) on {target}...")
                zone_transfer = test_zone_transfer(target)
                if zone_transfer.get("vulnerable"):
                    vuln_ns = ", ".join(zone_transfer.get("vulnerable_nameservers", []))
                    print(f"  {ColorCodes.BOLD}{ColorCodes.RED}[!] VULNERABLE: Zone transfer allowed on {vuln_ns}!{ColorCodes.RESET}")
                else:
                    logger.debug("DNS zone transfer refused (secure).")

            if not args.no_subdomains:
                logger.info(f"Discovering subdomains for {target} (crt.sh + dictionary)...")
                subdomains = enumerate_subdomains(target, max_workers=args.threads)
                if subdomains:
                    print(f"  {ColorCodes.GREEN}[+] Discovered {len(subdomains)} active subdomain(s):{ColorCodes.RESET}")
                    for sub, ips in list(subdomains.items())[:10]:
                        print(f"      {sub} -> {', '.join(ips)}")
                    if len(subdomains) > 10:
                        print(f"      {ColorCodes.DIM}...and {len(subdomains) - 10} more subdomains{ColorCodes.RESET}")

        # If domain failed to resolve and has no IPs, record report and continue
        if not resolved_ips:
            logger.warning(f"Could not resolve target: {target}")
            write_report(
                target=target,
                ip="",
                findings=[],
                dns_records=dns_records,
                subdomains=subdomains,
                zone_transfer=zone_transfer,
                alive=False,
                output_path=args.output_file,
                formats=[args.format],
            )
            continue

        # 3. Scan each resolved IP
        for ip in resolved_ips:
            ptr = reverse_dns(ip)
            if ptr:
                print(f"  {ColorCodes.DIM}[PTR]{ColorCodes.RESET} Reverse DNS for {ip}: {ptr}")

            # Host liveness check (ICMP + TCP Connect Ping)
            alive = True
            if not args.no_ping:
                logger.info(f"Checking host availability for {ip} (ICMP + TCP ping)...")
                alive = is_host_alive(ip)
                status_str = f"{ColorCodes.GREEN}ALIVE{ColorCodes.RESET}" if alive else f"{ColorCodes.YELLOW}UNRESPONSIVE TO PING (proceeding anyway){ColorCodes.RESET}"
                print(f"  [{'+' if alive else '-'}] Host {ip} is {status_str}")

            # Port & Service scan
            logger.info(f"Scanning ports [{args.ports}] on {ip}...")
            findings, os_info = scan(ip, port_spec=args.ports, hostname=target if is_domain else None)

            if os_info:
                print(f"  {ColorCodes.GREEN}[+] OS Detection:{ColorCodes.RESET}")
                for match in os_info:
                    print(f"      {match['name']} ({match['accuracy']}% confidence)")

            if not findings:
                print(f"  {ColorCodes.YELLOW}[!] No open TCP ports discovered on {ip}{ColorCodes.RESET}")
            else:
                print(f"\n  {ColorCodes.GREEN}[+] Found {len(findings)} open service(s) on {ip}:{ColorCodes.RESET}\n")

                # CVE Lookups & Enrichment
                for finding in findings:
                    if not args.no_cve:
                        check_cves(finding)
                    print_finding(finding)

            # Metadata compilation
            scan_end_timestamp = current_timestamp()
            duration = round(time.time() - start_monotonic, 2)
            metadata = {
                "scanner_version": "Reconnoiter 2.0.0",
                "command_line_args": " ".join(sys.argv[1:]),
                "scan_start_time": scan_start_timestamp,
                "scan_end_time": scan_end_timestamp,
                "scan_duration_seconds": duration,
                "ports_scanned": args.ports,
                "target": target,
                "ip": ip,
            }

            # 4. Write reports
            write_report(
                target=target,
                ip=ip,
                ip_addresses=resolved_ips,
                findings=findings,
                dns_records=dns_records,
                os_info=os_info,
                alive=alive,
                subdomains=subdomains,
                zone_transfer=zone_transfer,
                metadata=metadata,
                output_path=args.output_file,
                formats=[args.format],
            )

    total_time = round(time.time() - start_monotonic, 2)
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}[✓] Scan cycle completed in {total_time}s.{ColorCodes.RESET}\n")


if __name__ == "__main__":
    main()
