"""
Sentrix - Advanced Network Reconnaissance & Threat Assessment Pipeline
"""

import argparse
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

import cve_lookup
from cve_lookup import lookup_cves
from dns_enum import enumerate_dns, enumerate_subdomains, reverse_dns, test_zone_transfer
from host_discovery import is_host_alive
from report import write_report
from resolver import extract_target_port, is_ip_address, resolve_all_targets
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


def check_cves(finding: Dict[str, Any], bypass_cache: bool = False) -> Dict[str, Any]:
    """
    Resolves a scanner finding's CPE (if any) and looks up CVEs.
    Enriches with EPSS probabilities and CISA Known Exploited Vulnerability status.
    Assigns a distinct finding['cve_status']: 'matched', 'clean', 'no_cpe', or 'failed'.
    """
    cpe = finding.get("cpes")
    cpe_str = (cpe[0] if isinstance(cpe, list) and cpe else cpe) if cpe else None

    if not cpe_str:
        finding["cve_status"] = "no_cpe"
        finding["cves"] = []
        finding["cve_reason"] = "no_cpe_from_nmap"
        finding["cve_source"] = None
        return finding

    result = lookup_cves(cpe_str, bypass_cache=bypass_cache)
    raw_status = result.get("status")
    cves = result.get("cves", [])

    if raw_status == "matched" and cves:
        finding["cve_status"] = "matched"
    elif raw_status == "error":
        finding["cve_status"] = "failed"
    elif raw_status == "unmatched":
        reason = result.get("reason", "")
        if reason in ("no_cpe_available", "no_vendor_product"):
            finding["cve_status"] = "no_cpe"
        else:
            finding["cve_status"] = "clean"
    else:
        finding["cve_status"] = "clean" if not cves else "matched"

    finding["cves"] = cves
    finding["cve_reason"] = result.get("reason")
    finding["cve_source"] = result.get("source")
    finding["stale_cache"] = result.get("stale_cache", False)
    finding["version_unspecified"] = result.get("version_unspecified", False)
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
        b_text = finding["banner"].strip()
        if len(b_text) > 115:
            b_text = b_text[:112] + "..."
        print(f"    Banner  : {ColorCodes.DIM}{b_text}{ColorCodes.RESET}")

    if finding.get("waf_cdn"):
        print(f"    {ColorCodes.BOLD}{ColorCodes.MAGENTA}WAF/CDN :{ColorCodes.RESET} {finding['waf_cdn']}")

    if finding.get("technologies"):
        print(f"    {ColorCodes.CYAN}Stack   :{ColorCodes.RESET} {', '.join(finding['technologies'])}")

    if finding.get("security_headers") and finding["security_headers"].get("score"):
        sec = finding["security_headers"]
        missing_names = [m["header"].split()[0] for m in sec.get("missing", [])[:4]]
        missing_str = f"Missing: {', '.join(missing_names)}" if missing_names else "All recommended headers present"
        print(f"    {ColorCodes.YELLOW}Headers :{ColorCodes.RESET} OWASP Score {sec.get('score')} (Grade {sec.get('grade')}) - {missing_str}")

    if finding.get("tls_cert") and finding["tls_cert"].get("issuer"):
        cert = finding["tls_cert"]
        days = cert.get("days_until_expiry")
        days_str = f"{days} days" if days is not None else "N/A"
        self_signed_badge = f" {ColorCodes.RED}[SELF-SIGNED]{ColorCodes.RESET}" if cert.get("is_self_signed") else ""
        print(f"    {ColorCodes.DIM}TLS Cert:{ColorCodes.RESET} CN={cert.get('subject_cn')}{self_signed_badge} | Issuer={cert.get('issuer')} | Expiry: {days_str}")

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
        stale_badge = f" {ColorCodes.YELLOW}[STALE CACHE]{ColorCodes.RESET}" if finding.get("stale_cache") else ""
        print(f"    {ColorCodes.RED}CVEs [{source}]{stale_badge}:{ColorCodes.RESET} {len(cves)} found -> {', '.join(shown_items)}")
        if finding.get("version_unspecified"):
            print(f"        {ColorCodes.YELLOW}[i] Note: Exact version was not fingerprinted; CVEs cover the general software family.{ColorCodes.RESET}")
        if len(cves) > len(top):
            print(f"        {ColorCodes.DIM}...and {len(cves) - len(top)} more documented in report files{ColorCodes.RESET}")
    elif status == "clean":
        print(f"    {ColorCodes.GREEN}CVEs    : Confirmed clean (0 known CVEs across NVD/CIRCL){ColorCodes.RESET}")
    elif status == "no_cpe":
        print(f"    {ColorCodes.DIM}CVEs    : No CPE match (insufficient version fingerprinting){ColorCodes.RESET}")
    elif status == "failed":
        print(f"    {ColorCodes.BOLD}{ColorCodes.RED}CVEs    : Lookup failed — service unassessed ({finding.get('cve_reason', 'error')}){ColorCodes.RESET}")
    else:
        print(f"    {ColorCodes.DIM}CVEs    : No known match ({finding.get('cve_reason', 'clean')}){ColorCodes.RESET}")

    print("  " + "─" * 68)


def build_arg_parser() -> argparse.ArgumentParser:
    """Builds and returns the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentrix",
        description="Sentrix: Advanced Network Reconnaissance & Threat Assessment Pipeline",
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
        "--nvd-key",
        dest="nvd_key",
        help="NVD API key (raises rate limit from 5 to 50 requests/30s)",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help="NVD API key alias (compatible with --nvd-key)",
    )
    parser.add_argument(
        "--circl-key",
        dest="circl_key",
        help="CIRCL Vulnerability-Lookup API key (vulnerability.circl.lu)",
    )
    parser.add_argument(
        "--shodan-key",
        dest="shodan_key",
        help="Shodan API key for Shodan queries",
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
        "--no-cache",
        action="store_true",
        help="Bypass local SQLite CVE cache to force fresh threat intelligence queries",
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

    # Dual input mode: interactive prompt if no targets were passed on CLI
    if not args.targets and not args.input_file:
        print_banner()
        print(f"  {ColorCodes.CYAN}Sentrix Interactive Mode{ColorCodes.RESET} - No targets specified on command line.")
        try:
            prompt_str = f"  {ColorCodes.BOLD}sentrix > Enter target(s) (e.g. domain, IP, CIDR, URL): {ColorCodes.RESET}"
            user_input = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{ColorCodes.YELLOW}[!] Interactive session cancelled.{ColorCodes.RESET}")
            sys.exit(0)

        if not user_input:
            print(f"  {ColorCodes.YELLOW}[!] No target provided. Exiting.{ColorCodes.RESET}\n")
            sys.exit(0)

        raw_tokens = [t.strip() for t in re.split(r"[\s,;]+", user_input) if t.strip()]
        args.targets = raw_tokens
        logger = setup_logging(verbose=args.verbose)
    else:
        logger = setup_logging(verbose=args.verbose)
        print_banner()

    nvd_k = args.nvd_key or args.api_key
    if nvd_k:
        cve_lookup.set_nvd_key(nvd_k)
    if args.circl_key:
        cve_lookup.set_circl_key(args.circl_key)
    if args.shodan_key:
        cve_lookup.set_shodan_key(args.shodan_key)

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

        # Detect if any target specified an explicit port (e.g. https://cysclub.tech:8443)
        if args.targets:
            for raw_spec in args.targets:
                port = extract_target_port(raw_spec)
                if port and str(port) not in args.ports.split(","):
                    if args.ports == "top-200":
                        # If port is not in top-200, ensure it gets scanned
                        args.ports = f"top-200,{port}"
                    else:
                        args.ports = f"{args.ports},{port}"

        if not resolved_map:
            logger.error("No valid targets identified.")
            sys.exit(1)

        logger.info(f"Loaded {len(resolved_map)} target specification(s) for assessment.")

        for target, resolved_ips in resolved_map.items():
            # Target configuration ASCII frame
            threat_intel_label = "NIST NVD 2.0 (SQLite 7d TTL) + CIRCL + Shodan InternetDB + CISA KEV + EPSS"
            frame_lines = [
                f"Target Specifier : {ColorCodes.BOLD}{target}{ColorCodes.RESET}",
                f"Resolved IPs     : {', '.join(resolved_ips) if resolved_ips else 'Unresolved'}",
                f"Port Scope       : {args.ports} (Worker Threads: {args.threads})",
                f"Liveness Probe   : {'Bypassed (--no-ping)' if args.no_ping else 'Hybrid ICMP Echo + TCP Connect Ping'}",
                f"Threat Intel     : {threat_intel_label}",
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

            all_findings: List[Dict[str, Any]] = []
            all_os_info: List[Dict[str, Any]] = []
            active_scanned_ips: List[str] = []
            any_alive = False
            target_shodan_intel: Dict[str, Any] = {}

            # 3. Scan each resolved IP
            for ip in resolved_ips:
                draw_section_header(f"PHASE 2: HOST DISCOVERY & PORT INTELLIGENCE [{ip}]")
                ptr = reverse_dns(ip)
                if ptr:
                    print(f"  {ColorCodes.DIM}[PTR]{ColorCodes.RESET} Reverse DNS for {ip}: {ptr}")

                # Shodan InternetDB threat intelligence
                shodan_data = cve_lookup.query_shodan_internetdb(ip, bypass_cache=args.no_cache)
                if shodan_data and shodan_data.get("status") == "found":
                    target_shodan_intel[ip] = shodan_data
                    s_tags = shodan_data.get("tags", [])
                    s_vulns = shodan_data.get("vulns", [])
                    s_ports = shodan_data.get("ports", [])
                    s_hosts = shodan_data.get("hostnames", [])
                    info_parts = []
                    if s_tags:
                        info_parts.append(f"Tags: [{', '.join(s_tags)}]")
                    if s_hosts:
                        info_parts.append(f"Hostnames: {', '.join(s_hosts[:3])}")
                    if s_vulns:
                        info_parts.append(f"{ColorCodes.RED}Known Vulns: {len(s_vulns)} ({', '.join(s_vulns[:4])}{'...' if len(s_vulns) > 4 else ''}){ColorCodes.RESET}")
                    if s_ports:
                        info_parts.append(f"Observed Ports: {s_ports[:8]}")
                    if info_parts:
                        print(f"  {ColorCodes.CYAN}[Shodan InternetDB]{ColorCodes.RESET} {' | '.join(info_parts)}")

                # Host liveness check (ICMP + TCP Connect Ping)
                alive = True
                if not args.no_ping:
                    logger.info(f"Checking host availability for {ip} (ICMP + TCP ping)...")
                    alive = is_host_alive(ip)
                    if not alive:
                        print(f"  [-] Host {ip} is {ColorCodes.YELLOW}OFFLINE / UNRESPONSIVE{ColorCodes.RESET} to ICMP & TCP probes.")
                        print(f"      {ColorCodes.DIM}(Skipping port scan for this IP. Pass --no-ping to force full scan){ColorCodes.RESET}")
                        draw_section_footer()
                        continue
                    else:
                        print(f"  [+] Host {ip} status: {ColorCodes.GREEN}ALIVE{ColorCodes.RESET}")

                any_alive = True
                active_scanned_ips.append(ip)

                # Port & Service scan
                logger.info(f"Scanning ports [{args.ports}] on {ip}...")
                findings, os_info = scan(ip, port_spec=args.ports, hostname=target if is_domain else None)

                # Harvest TLS SAN hostnames into subdomains
                if is_domain:
                    for f in findings:
                        cert = f.get("tls_cert")
                        if cert and cert.get("sans"):
                            for san in cert["sans"]:
                                san_clean = san.lower().strip()
                                if san_clean.startswith("*."):
                                    san_clean = san_clean[2:]
                                if (san_clean.endswith(f".{target.lower()}") or san_clean == target.lower()) and san_clean not in subdomains:
                                    subdomains[san_clean] = [ip]

                if os_info:
                    print(f"  {ColorCodes.GREEN}[+]{ColorCodes.RESET} OS Detection matches:")
                    for match in os_info:
                        print(f"      • {match['name']} ({match['accuracy']}% accuracy)")
                    all_os_info.extend(os_info)

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
                        finding["ip"] = ip
                        if not args.no_cve:
                            check_cves(finding, bypass_cache=args.no_cache)
                        print_finding(finding)
                    draw_section_footer()

                    all_findings.extend(findings)

            # 4. Consolidated Target Reporting & Assessment Dashboard
            scan_end_timestamp = current_timestamp()
            duration = round(time.time() - start_monotonic, 2)
            primary_ip = active_scanned_ips[0] if active_scanned_ips else (resolved_ips[0] if resolved_ips else "")
            target_alive = any_alive or args.no_ping

            metadata = {
                "scanner_version": "Sentrix 2.1.0",
                "command_line_args": " ".join(sys.argv[1:]),
                "scan_start_time": scan_start_timestamp,
                "scan_end_time": scan_end_timestamp,
                "scan_duration_seconds": duration,
                "ports_scanned": args.ports,
                "target": target,
                "ip": primary_ip,
                "all_ips": resolved_ips,
                "active_ips": active_scanned_ips,
                "shodan_intel": target_shodan_intel,
            }

            written_files = write_report(
                target=target,
                ip=primary_ip,
                ip_addresses=resolved_ips,
                findings=all_findings,
                dns_records=dns_records,
                os_info=all_os_info,
                alive=target_alive,
                subdomains=subdomains,
                zone_transfer=zone_transfer,
                metadata=metadata,
                output_path=args.output_file,
                formats=[args.format],
            )

            # Count statistics for summary card
            total_services = len(all_findings)
            failed_services = [f for f in all_findings if f.get("cve_status") == "failed"]
            no_cpe_services = [f for f in all_findings if f.get("cve_status") == "no_cpe"]
            crit_count = sum(1 for f in all_findings for c in f.get("cves", []) if c.get("severity") == "CRITICAL" or (c.get("cvss") or 0) >= 9.0)
            kev_count = sum(1 for f in all_findings for c in f.get("cves", []) if c.get("cisa_kev"))
            total_cves = sum(len(f.get("cves", [])) for f in all_findings)

            # Worst-case summary outcome calculation:
            # Must distinguish:
            # - 0 CVEs (no CPE match)
            # - 0 CVEs (lookup failed — N/N services unassessed)
            # - 0 CVEs (confirmed clean)
            # Never collapse "failed" into "0"
            if total_cves > 0:
                if failed_services:
                    cve_summary_line = f"{total_cves} (Critical: {crit_count}) — ⚠️ {len(failed_services)}/{total_services} service lookups failed"
                else:
                    cve_summary_line = f"{total_cves} (Critical CVSS 9.0+: {crit_count})"
            elif total_services == 0:
                cve_summary_line = "0 (No open services)"
            else:
                if failed_services:
                    cve_summary_line = f"0 CVEs (lookup failed — {len(failed_services)}/{total_services} services unassessed)"
                elif no_cpe_services:
                    cve_summary_line = "0 CVEs (no CPE match)"
                else:
                    cve_summary_line = "0 CVEs (confirmed clean)"

            # Final Assessment Dashboard Frame
            liveness_str = f"{ColorCodes.GREEN}ALIVE{ColorCodes.RESET}" if target_alive else f"{ColorCodes.YELLOW}OFFLINE / UNRESPONSIVE{ColorCodes.RESET}"
            ip_display = ", ".join(active_scanned_ips) if active_scanned_ips else primary_ip
            summary_lines = [
                f"Target Assessment  : {ColorCodes.BOLD}{target}{ColorCodes.RESET} ({ip_display})",
                f"Host Liveness      : {liveness_str}",
                f"Scan Duration      : {duration}s",
                f"Open Services      : {total_services} discovered across scanned IPs",
                f"Total CVEs Found   : {cve_summary_line}",
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
