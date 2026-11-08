"""
Reconnoiter - Advanced Network Reconnaissance & Vulnerability Assessment Pipeline
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
from utils import (
    ColorCodes,
    current_timestamp,
    draw_frame,
    draw_section_footer,
    draw_section_header,
    format_table,
    print_banner,
    setup_logging,
)


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

    print(f"  {ColorCodes.GREEN}►{ColorCodes.RESET} Service : {svc_str} on Port {port_str} {ColorCodes.DIM}({info}){ColorCodes.RESET}")
    if finding.get("banner"):
        print(f"    Banner  : {ColorCodes.DIM}{finding['banner'][:100]}{ColorCodes.RESET}")

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
        print(f"    {ColorCodes.RED}CVEs [{source}]:{ColorCodes.RESET} {len(cves)} found -> {', '.join(shown_items)}")
        if len(cves) > len(top):
            print(f"        {ColorCodes.DIM}...and {len(cves) - len(top)} more documented in report files{ColorCodes.RESET}")
    elif status == "unmatched":
        print(f"    {ColorCodes.DIM}CVEs    : No known match ({finding.get('cve_reason', 'clean')}){ColorCodes.RESET}")
    else:
        print(f"    {ColorCodes.YELLOW}CVEs    : Lookup notice ({finding.get('cve_reason', 'unknown')}){ColorCodes.RESET}")

    print("  " + "─" * 68)


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

    try:
        # 1. Expand and resolve all target specifications
        logger.info("Resolving target specifications and IP mappings...")
        try:
            resolved_map = resolve_all_targets(args.targets, args.input_file)
        except Exception as e:
            logger.error(f"Failed to process targets: {e}")
            sys.exit(1)

        if not resolved_map:
            logger.error("No valid targets identified.")
            sys.exit(1)

        logger.info(f"Loaded {len(resolved_map)} target specification(s) for assessment.")

        for target, resolved_ips in resolved_map.items():
            # Target configuration ASCII frame
            frame_lines = [
                f"Target Specifier : {ColorCodes.BOLD}{target}{ColorCodes.RESET}",
                f"Resolved IPs     : {', '.join(resolved_ips) if resolved_ips else 'Unresolved'}",
                f"Port Scope       : {args.ports} (Worker Threads: {args.threads})",
                f"Liveness Probe   : {'Bypassed (--no-ping)' if args.no_ping else 'Hybrid ICMP Echo + TCP Connect Ping'}",
                f"Threat Intel     : NIST NVD 2.0 (SQLite 7d TTL) + CISA KEV + FIRST EPSS",
                f"Output Format    : {args.format.upper()} (Output: {args.output_file or 'reports/'})",
            ]
            print(draw_frame("TARGET ASSESSMENT CONFIGURATION", frame_lines, color=ColorCodes.CYAN))

            is_domain = not is_ip_address(target)
            dns_records: Dict[str, List[str]] = {}
            subdomains: Dict[str, List[str]] = {}
            zone_transfer: Dict[str, Any] = {}

            # 2. DNS Reconnaissance (for domain targets)
            if is_domain:
                draw_section_header("PHASE 1: DNS & SUBDOMAIN RECONNAISSANCE")
                logger.info(f"Enumerating DNS records for {target}...")
                dns_records = enumerate_dns(target)
                for rtype, vals in dns_records.items():
                    if vals:
                        print(f"  {ColorCodes.DIM}[DNS]{ColorCodes.RESET} {rtype:5s}: {', '.join(vals)}")

                if not args.no_axfr:
                    logger.info(f"Testing DNS zone transfer (AXFR) on {target}...")
                    zone_transfer = test_zone_transfer(target)
                    if zone_transfer.get("vulnerable"):
                        vuln_ns = ", ".join(zone_transfer.get("vulnerable_nameservers", []))
                        print(f"  {ColorCodes.BOLD}{ColorCodes.RED}[!] VULNERABLE: Zone transfer allowed on {vuln_ns}!{ColorCodes.RESET}")
                    else:
                        print(f"  {ColorCodes.GREEN}[✓]{ColorCodes.RESET} Zone Transfer (AXFR): Refused / Secure across authoritative nameservers")

                if not args.no_subdomains:
                    logger.info(f"Discovering subdomains for {target} (crt.sh + dictionary)...")
                    subdomains = enumerate_subdomains(target, max_workers=args.threads)
                    if subdomains:
                        print(f"  {ColorCodes.GREEN}[+]{ColorCodes.RESET} Discovered {len(subdomains)} active subdomain(s):")
                        for sub, ips in list(subdomains.items())[:8]:
                            print(f"      • {sub:30s} -> {', '.join(ips)}")
                        if len(subdomains) > 8:
                            print(f"      {ColorCodes.DIM}...and {len(subdomains) - 8} additional subdomains recorded{ColorCodes.RESET}")
                draw_section_footer()

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
                draw_section_header(f"PHASE 2: HOST DISCOVERY & PORT INTELLIGENCE [{ip}]")
                ptr = reverse_dns(ip)
                if ptr:
                    print(f"  {ColorCodes.DIM}[PTR]{ColorCodes.RESET} Reverse DNS for {ip}: {ptr}")

                # Host liveness check (ICMP + TCP Connect Ping)
                alive = True
                if not args.no_ping:
                    logger.info(f"Checking host availability for {ip} (ICMP + TCP ping)...")
                    alive = is_host_alive(ip)
                    status_str = f"{ColorCodes.GREEN}ALIVE{ColorCodes.RESET}" if alive else f"{ColorCodes.YELLOW}UNRESPONSIVE TO PING (proceeding anyway){ColorCodes.RESET}"
                    print(f"  [{'+' if alive else '-'}] Host {ip} status: {status_str}")

                # Port & Service scan
                logger.info(f"Scanning ports [{args.ports}] on {ip}...")
                findings, os_info = scan(ip, port_spec=args.ports, hostname=target if is_domain else None)

                if os_info:
                    print(f"  {ColorCodes.GREEN}[+]{ColorCodes.RESET} OS Detection matches:")
                    for match in os_info:
                        print(f"      • {match['name']} ({match['accuracy']}% accuracy)")

                if not findings:
                    print(f"  {ColorCodes.YELLOW}[!] No open TCP ports discovered on {ip}{ColorCodes.RESET}")
                    draw_section_footer()
                else:
                    # Print boxed table of discovered open services
                    table_headers = ["Port/Proto", "Service", "Product", "Version", "Banner Preview"]
                    table_rows = [
                        [
                            f"{f['port']}/{f.get('protocol', 'tcp')}",
                            f.get("service", "unknown"),
                            f.get("product", "")[:16],
                            f.get("version", "")[:12],
                            f.get("banner", "")[:28],
                        ]
                        for f in findings
                    ]
                    print(format_table(table_headers, table_rows))
                    draw_section_footer()

                    # Phase 3: Vulnerability Intelligence
                    draw_section_header(f"PHASE 3: THREAT INTELLIGENCE & CVE AUDIT [{ip}]")
                    for finding in findings:
                        if not args.no_cve:
                            check_cves(finding)
                        print_finding(finding)
                    draw_section_footer()

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
                written_files = write_report(
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

                # Count statistics for summary card
                crit_count = sum(1 for f in findings for c in f.get("cves", []) if c.get("severity") == "CRITICAL" or (c.get("cvss") or 0) >= 9.0)
                kev_count = sum(1 for f in findings for c in f.get("cves", []) if c.get("cisa_kev"))
                total_cves = sum(len(f.get("cves", [])) for f in findings)

                # Final Assessment Dashboard Frame
                liveness_str = f"{ColorCodes.GREEN}ALIVE{ColorCodes.RESET}" if alive else f"{ColorCodes.YELLOW}OFFLINE / UNRESPONSIVE{ColorCodes.RESET}"
                summary_lines = [
                    f"Target Assessment  : {ColorCodes.BOLD}{target}{ColorCodes.RESET} ({ip})",
                    f"Host Liveness      : {liveness_str}",
                    f"Scan Duration      : {duration}s",
                    f"Open Services      : {len(findings)} discovered",
                    f"Total CVEs Found   : {total_cves} (Critical CVSS 9.0+: {crit_count})",
                    f"CISA KEV Status    : {f'{ColorCodes.BOLD}{ColorCodes.RED}⚠️ {kev_count} ACTIVELY EXPLOITED IN WILD{ColorCodes.RESET}' if kev_count else f'{ColorCodes.GREEN}No known active exploits{ColorCodes.RESET}'}",
                    f"Zone Transfer Leak : {f'{ColorCodes.BOLD}{ColorCodes.RED}YES (VULNERABLE){ColorCodes.RESET}' if zone_transfer.get('vulnerable') else 'No (Refused)'}",
                    f"Subdomains Found   : {len(subdomains)} active",
                    f"Generated Reports  : {', '.join(written_files)}",
                ]
                print(draw_frame("ASSESSMENT SUMMARY DASHBOARD", summary_lines, color=ColorCodes.GREEN))

        total_time = round(time.time() - start_monotonic, 2)
        print(f"{ColorCodes.GREEN}{ColorCodes.BOLD}[✓] Scan cycle fully completed in {total_time}s.{ColorCodes.RESET}\n")

    except KeyboardInterrupt:
        print(f"\n\n{ColorCodes.YELLOW}[!] Scan interrupted by user. Exiting cleanly.{ColorCodes.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
