"""
Multi-format report generation (JSON, HTML, Markdown) with CVSS color-coding,
EPSS exploitation probabilities, CISA KEV alerts, and automated remediation guidance.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

from utils import current_timestamp

REPORT_DIR = "reports"


def _sanitize_filename(name: str) -> str:
    """Replaces characters unsafe for file systems."""
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)


def _compute_summary(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Computes summary KPI counters for vulnerabilities, ports, and threat alerts."""
    services = report_data.get("services", [])
    open_ports = [s.get("port") for s in services if "port" in s]

    total_cves = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    kev_count = 0
    high_epss_count = 0

    seen_cves = set()
    for s in services:
        for cve in s.get("cves", []):
            cid = cve.get("id")
            if cid and cid not in seen_cves:
                seen_cves.add(cid)
                total_cves += 1

                sev = str(cve.get("severity", "")).upper()
                cvss = cve.get("cvss") or 0.0

                if sev == "CRITICAL" or cvss >= 9.0:
                    critical_count += 1
                elif sev == "HIGH" or cvss >= 7.0:
                    high_count += 1
                elif sev == "MEDIUM" or cvss >= 4.0:
                    medium_count += 1
                elif sev == "LOW" or cvss > 0.0:
                    low_count += 1

                if cve.get("cisa_kev"):
                    kev_count += 1

                epss = cve.get("epss") or 0.0
                if epss >= 0.10:  # 10%+ probability
                    high_epss_count += 1

    return {
        "total_services": len(services),
        "open_ports": open_ports,
        "total_cves": total_cves,
        "critical_cves": critical_count,
        "high_cves": high_count,
        "medium_cves": medium_count,
        "low_cves": low_count,
        "cisa_kev_cves": kev_count,
        "high_epss_cves": high_epss_count,
    }


def _generate_remediations(report_data: Dict[str, Any], summary: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generates actionable security hardening and remediation recommendations."""
    remediations: List[Dict[str, str]] = []

    if summary.get("cisa_kev_cves", 0) > 0:
        remediations.append({
            "title": "Immediate Patching of CISA KEV Vulnerabilities",
            "priority": "CRITICAL",
            "description": f"{summary['cisa_kev_cves']} vulnerability(ies) detected are actively weaponized and exploited by threat actors in the wild. Apply vendor security updates immediately according to CISA guidelines.",
        })

    zone_xfr = report_data.get("zone_transfer", {})
    if zone_xfr.get("vulnerable"):
        vuln_ns = ", ".join(zone_xfr.get("vulnerable_nameservers", []))
        remediations.append({
            "title": "Restrict Unauthenticated DNS Zone Transfers (AXFR)",
            "priority": "HIGH",
            "description": f"Nameserver(s) ({vuln_ns}) allow unauthenticated AXFR requests, revealing full internal network topologies. Restrict zone transfers to authorized secondary nameserver IPs only.",
        })

    services = report_data.get("services", [])
    open_ports = [s.get("port") for s in services]

    if 21 in open_ports:
        remediations.append({
            "title": "Deprecate Plaintext FTP (Port 21)",
            "priority": "MEDIUM",
            "description": "Port 21 is exposed. FTP transmits credentials in cleartext. Migrate to SFTP (SSH File Transfer Protocol) or FTPS.",
        })

    if 23 in open_ports:
        remediations.append({
            "title": "Disable Unencrypted Telnet (Port 23)",
            "priority": "CRITICAL",
            "description": "Telnet communicates in plaintext. Disable Telnet immediately and replace with SSHv2.",
        })

    if 80 in open_ports and 443 not in open_ports:
        remediations.append({
            "title": "Enforce HTTPS & TLS Encryption",
            "priority": "MEDIUM",
            "description": "HTTP port 80 is open without an active HTTPS listener. Implement TLS certificates (e.g. Let's Encrypt) and enforce HTTP Strict Transport Security (HSTS).",
        })

    if summary.get("critical_cves", 0) > 0 or summary.get("high_cves", 0) > 0:
        remediations.append({
            "title": "Upgrade Exposed Outdated Services",
            "priority": "HIGH",
            "description": "Discovered services contain critical/high CVSS vulnerabilities. Update server software packages to latest stable releases and apply security patches.",
        })

    if not remediations:
        remediations.append({
            "title": "Maintain Baseline Security Hygiene",
            "priority": "INFO",
            "description": "No critical misconfigurations or actively exploited CVEs were detected. Continue periodic vulnerability scans and maintain regular patch schedules.",
        })

    return remediations


def generate_json_report(report_data: Dict[str, Any]) -> str:
    """Formats report data as formatted JSON."""
    return json.dumps(report_data, indent=4)


def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    """Formats report data as structured GitHub-flavored Markdown."""
    meta = report_data.get("metadata", {})
    summary = report_data.get("summary", {})
    services = report_data.get("services", [])
    dns_records = report_data.get("dns_records", {})
    subdomains = report_data.get("subdomains", {})
    zone_transfer = report_data.get("zone_transfer", {})
    remediations = report_data.get("remediations", [])

    lines = [
        f"# Reconnoiter Security Assessment Report: {report_data.get('target')}",
        "",
        "## Executive Summary",
        "",
        f"- **Target**: `{report_data.get('target')}`",
        f"- **Resolved IP(s)**: {', '.join(f'`{ip}`' for ip in report_data.get('ip_addresses', [])) or report_data.get('ip', 'N/A')}",
        f"- **Host Liveness**: `{'ALIVE' if report_data.get('alive') else 'UNRESPONSIVE'}`",
        f"- **Scan Duration**: `{meta.get('scan_duration_seconds', 'N/A')} seconds`",
        f"- **Timestamp**: `{report_data.get('scan_time', meta.get('scan_start_time', 'N/A'))}`",
        f"- **Scanner Version**: `{meta.get('scanner_version', 'Reconnoiter')}`",
        "",
        "### Key Findings Overview",
        "",
        "| Metric | Count |",
        "| :--- | :--- |",
        f"| Open Ports / Services | **{summary.get('total_services', 0)}** |",
        f"| Total Discovered CVEs | **{summary.get('total_cves', 0)}** |",
        f"| Critical Severity (CVSS 9.0+) | **{summary.get('critical_cves', 0)}** |",
        f"| High Severity (CVSS 7.0-8.9) | **{summary.get('high_cves', 0)}** |",
        f"| CISA Known Exploited (KEV) | **{summary.get('cisa_kev_cves', 0)}** |",
        f"| High Probability Exploits (EPSS ≥10%) | **{summary.get('high_epss_cves', 0)}** |",
        f"| Subdomains Discovered | **{len(subdomains)}** |",
        f"| Zone Transfer (AXFR) Leak | **{'YES (VULNERABLE)' if zone_transfer.get('vulnerable') else 'NO (SECURE)'}** |",
        "",
        "## Open Services & Banner Intelligence",
        "",
    ]

    if services:
        lines.extend([
            "| Port | Service | Product | Version | Banner | CVEs |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for s in services:
            banner_snippet = (s.get("banner", "")[:40] + "...") if len(s.get("banner", "")) > 40 else s.get("banner", "")
            lines.append(
                f"| `{s.get('port')}/{s.get('protocol', 'tcp')}` | {s.get('service', '')} | {s.get('product', '')} | {s.get('version', '')} | `{banner_snippet}` | {len(s.get('cves', []))} |"
            )
    else:
        lines.append("*No open services detected.*")

    lines.append("")
    lines.append("## Vulnerability Intelligence (CVSS, EPSS & CISA KEV)")
    lines.append("")

    all_cves: List[Dict[str, Any]] = []
    for s in services:
        for c in s.get("cves", []):
            entry = dict(c)
            entry["port"] = s.get("port")
            entry["service"] = s.get("service")
            all_cves.append(entry)

    if all_cves:
        lines.extend([
            "| CVE ID | Severity | CVSS | EPSS % | CISA KEV | Service / Port |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for c in all_cves[:50]:
            epss_str = f"{(c.get('epss', 0.0) * 100):.1f}%" if c.get("epss") is not None else "N/A"
            kev_str = "**YES** (Exploited)" if c.get("cisa_kev") else "No"
            lines.append(
                f"| [{c.get('id')}](https://nvd.nist.gov/vuln/detail/{c.get('id')}) | {c.get('severity', 'UNKNOWN')} | {c.get('cvss', 'N/A')} | {epss_str} | {kev_str} | `{c.get('service')}:{c.get('port')}` |"
            )
        if len(all_cves) > 50:
            lines.append(f"\n*...and {len(all_cves) - 50} additional CVEs in full report data.*")
    else:
        lines.append("*No matched CVEs found for discovered services.*")

    lines.append("")
    lines.append("## DNS & Subdomain Enumeration")
    lines.append("")

    if zone_transfer.get("vulnerable"):
        lines.append("> [!WARNING] **CRITICAL**: Authoritative nameserver allows AXFR zone transfers!")
        lines.append(f"> Vulnerable Nameservers: {', '.join(zone_transfer.get('vulnerable_nameservers', []))}")
        lines.append("")

    if subdomains:
        lines.extend([
            "| Subdomain | Resolved IP(s) |",
            "| :--- | :--- |",
        ])
        for sub, ips in subdomains.items():
            lines.append(f"| `{sub}` | {', '.join(ips) if ips else 'Unresolved'} |")
    else:
        lines.append("*No additional subdomains discovered.*")

    lines.append("")
    lines.append("## Remediation Guidance")
    lines.append("")
    for rem in remediations:
        lines.append(f"### [{rem.get('priority')}] {rem.get('title')}")
        lines.append(f"{rem.get('description')}\n")

    return "\n".join(lines)


def generate_html_report(report_data: Dict[str, Any]) -> str:
    """Generates an HTML report with dark cybersecurity aesthetic, charts, and badges."""
    meta = report_data.get("metadata", {})
    summary = report_data.get("summary", {})
    services = report_data.get("services", [])
    dns_records = report_data.get("dns_records", {})
    subdomains = report_data.get("subdomains", {})
    zone_transfer = report_data.get("zone_transfer", {})
    remediations = report_data.get("remediations", [])

    all_cves: List[Dict[str, Any]] = []
    for s in services:
        for c in s.get("cves", []):
            entry = dict(c)
            entry["port"] = s.get("port")
            entry["service"] = s.get("service")
            all_cves.append(entry)

    cve_rows_html = ""
    for c in all_cves:
        sev = str(c.get("severity", "UNKNOWN")).upper()
        badge_cls = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
        }.get(sev, "badge-unknown")

        epss_val = c.get("epss")
        epss_str = f"{(epss_val * 100):.1f}%" if epss_val is not None else "N/A"
        kev_badge = '<span class="badge-kev">⚠️ EXPLOITED IN WILD</span>' if c.get("cisa_kev") else '<span class="badge-safe">Clean</span>'

        cve_rows_html += f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{c.get('id')}" target="_blank" class="cve-link">{c.get('id')}</a></td>
            <td><span class="{badge_cls}">{sev}</span></td>
            <td><strong>{c.get('cvss', 'N/A')}</strong></td>
            <td>{epss_str}</td>
            <td>{kev_badge}</td>
            <td><code>{c.get('service')}:{c.get('port')}</code></td>
        </tr>
        """

    services_rows_html = ""
    for s in services:
        banner = s.get("banner", "")
        services_rows_html += f"""
        <tr>
            <td><strong>{s.get('port')}/{s.get('protocol', 'tcp')}</strong></td>
            <td>{s.get('service', 'unknown')}</td>
            <td>{s.get('product', '')}</td>
            <td>{s.get('version', '')}</td>
            <td><div class="banner-cell">{banner if banner else '<span class="dim">No banner</span>'}</div></td>
            <td><span class="badge-count">{len(s.get('cves', []))}</span></td>
        </tr>
        """

    subdomain_rows_html = ""
    for sub, ips in subdomains.items():
        ip_list = ", ".join(ips) if ips else "Unresolved"
        subdomain_rows_html += f"<tr><td><code>{sub}</code></td><td>{ip_list}</td></tr>"

    remediation_cards_html = ""
    for rem in remediations:
        prio = rem.get("priority", "INFO")
        prio_color = {
            "CRITICAL": "#e63946",
            "HIGH": "#f77f00",
            "MEDIUM": "#fcbf49",
            "LOW": "#48cae4",
        }.get(prio, "#6c757d")

        remediation_cards_html += f"""
        <div class="remediation-card" style="border-left: 5px solid {prio_color};">
            <div class="rem-header">
                <span class="rem-priority" style="background-color: {prio_color};">{prio}</span>
                <span class="rem-title">{rem.get('title')}</span>
            </div>
            <p class="rem-desc">{rem.get('description')}</p>
        </div>
        """

    axfr_alert_html = ""
    if zone_transfer.get("vulnerable"):
        axfr_alert_html = f"""
        <div class="alert-box alert-critical">
            <h3>🚨 CRITICAL VULNERABILITY: DNS ZONE TRANSFER (AXFR) EXPOSED</h3>
            <p>Authoritative nameservers ({', '.join(zone_transfer.get('vulnerable_nameservers', []))}) permit full unauthenticated zone transfers, exposing internal domain architecture.</p>
        </div>
        """

    total_sev = (summary.get("critical_cves", 0) + summary.get("high_cves", 0) +
                 summary.get("medium_cves", 0) + summary.get("low_cves", 0)) or 1
    crit_pct = (summary.get("critical_cves", 0) / total_sev) * 100
    high_pct = (summary.get("high_cves", 0) / total_sev) * 100
    med_pct = (summary.get("medium_cves", 0) / total_sev) * 100
    low_pct = (summary.get("low_cves", 0) / total_sev) * 100

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnoiter Report: {report_data.get('target')}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #38bdf8;
            --accent: #6366f1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--surface);
            padding: 30px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 25px;
        }}
        .header-title {{ font-size: 26px; font-weight: 700; color: #fff; display: flex; align-items: center; justify-content: space-between; }}
        .header-meta {{ margin-top: 15px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; color: var(--text-muted); font-size: 14px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .kpi-card {{
            background: var(--surface);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        .kpi-num {{ font-size: 32px; font-weight: 800; margin-top: 5px; }}
        .kpi-label {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
        .bar-container {{ height: 12px; border-radius: 6px; overflow: hidden; display: flex; margin: 20px 0; background: #334155; }}
        .bar-crit {{ background-color: var(--critical); width: {crit_pct}%; }}
        .bar-high {{ background-color: var(--high); width: {high_pct}%; }}
        .bar-med {{ background-color: var(--medium); width: {med_pct}%; }}
        .bar-low {{ background-color: var(--low); width: {low_pct}%; }}
        .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 25px; margin-bottom: 25px; }}
        .section-title {{ font-size: 20px; margin-bottom: 15px; font-weight: 600; color: #fff; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: rgba(255, 255, 255, 0.03); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background-color: var(--surface-hover); }}
        code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #38bdf8; }}
        .banner-cell {{ max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 12px; color: #cbd5e1; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .badge-low {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .badge-unknown {{ background: #475569; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 11px; }}
        .badge-kev {{ background: #ef4444; color: #fff; padding: 4px 8px; border-radius: 4px; font-weight: 800; font-size: 11px; animation: pulse 2s infinite; }}
        .badge-safe {{ color: #10b981; font-size: 12px; }}
        .badge-count {{ background: #3b82f6; color: #fff; padding: 2px 7px; border-radius: 10px; font-size: 11px; font-weight: 700; }}
        .cve-link {{ color: #60a5fa; text-decoration: none; font-weight: 600; }}
        .cve-link:hover {{ text-decoration: underline; }}
        .remediation-card {{ background: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
        .rem-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .rem-priority {{ color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .rem-title {{ font-size: 16px; font-weight: 600; }}
        .rem-desc {{ color: var(--text-muted); font-size: 14px; }}
        .alert-box {{ padding: 18px; border-radius: 8px; margin-bottom: 20px; }}
        .alert-critical {{ background: rgba(239, 68, 68, 0.15); border: 1px solid var(--critical); color: #fca5a5; }}
        .alert-box h3 {{ color: #fff; margin-bottom: 6px; }}
        .dim {{ color: #64748b; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <div>Reconnoiter Assessment: <code>{report_data.get('target')}</code></div>
                <div style="font-size: 14px; font-weight: normal; color: var(--text-muted);">{meta.get('scanner_version', 'Reconnoiter 2.0')}</div>
            </div>
            <div class="header-meta">
                <div><strong>Host Status:</strong> <span style="color: {'#10b981' if report_data.get('alive') else '#ef4444'}; font-weight: bold;">{'ALIVE' if report_data.get('alive') else 'OFFLINE'}</span></div>
                <div><strong>Resolved IP:</strong> <code>{', '.join(report_data.get('ip_addresses', [])) or report_data.get('ip', 'N/A')}</code></div>
                <div><strong>Duration:</strong> {meta.get('scan_duration_seconds', 'N/A')}s</div>
                <div><strong>Scan Time:</strong> {report_data.get('scan_time', meta.get('scan_start_time', 'N/A'))}</div>
            </div>
        </header>

        {axfr_alert_html}

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Open Ports</div>
                <div class="kpi-num" style="color: #38bdf8;">{summary.get('total_services', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total CVEs</div>
                <div class="kpi-num" style="color: #cbd5e1;">{summary.get('total_cves', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">CISA KEV (Exploited)</div>
                <div class="kpi-num" style="color: var(--critical);">{summary.get('cisa_kev_cves', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Critical Severity</div>
                <div class="kpi-num" style="color: var(--critical);">{summary.get('critical_cves', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">High Severity</div>
                <div class="kpi-num" style="color: var(--high);">{summary.get('high_cves', 0)}</div>
            </div>
        </div>

        <div class="bar-container">
            <div class="bar-crit" title="Critical"></div>
            <div class="bar-high" title="High"></div>
            <div class="bar-med" title="Medium"></div>
            <div class="bar-low" title="Low"></div>
        </div>

        <div class="section">
            <div class="section-title">Open Services & Port Fingerprints</div>
            <table>
                <thead>
                    <tr>
                        <th>Port/Proto</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Raw Banner</th>
                        <th>CVE Count</th>
                    </tr>
                </thead>
                <tbody>
                    {services_rows_html if services_rows_html else '<tr><td colspan="6" class="dim">No open services discovered.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <div class="section-title">Vulnerability Intelligence (CVSS, EPSS & CISA KEV)</div>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Severity</th>
                        <th>CVSS Score</th>
                        <th>EPSS Prob</th>
                        <th>Threat Status</th>
                        <th>Affected Target</th>
                    </tr>
                </thead>
                <tbody>
                    {cve_rows_html if cve_rows_html else '<tr><td colspan="6" class="dim">No matching CVEs detected for active services.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <div class="section-title">Discovered Subdomains & DNS Infrastructure</div>
            <table>
                <thead>
                    <tr>
                        <th>Discovered Subdomain</th>
                        <th>Associated IP Addresses</th>
                    </tr>
                </thead>
                <tbody>
                    {subdomain_rows_html if subdomain_rows_html else '<tr><td colspan="2" class="dim">No additional subdomains resolved.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <div class="section-title">Security Remediation & Hardening Recommendations</div>
            <div>
                {remediation_cards_html}
            </div>
        </div>
    </div>
</body>
</html>
"""
    return html


def write_report(
    target: str,
    ip: str,
    findings: List[Dict[str, Any]],
    dns_records: Optional[Dict[str, List[str]]] = None,
    os_info: Optional[List[Dict[str, Any]]] = None,
    alive: Optional[bool] = None,
    subdomains: Optional[Dict[str, List[str]]] = None,
    zone_transfer: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    output_path: Optional[str] = None,
    formats: Optional[List[str]] = None,
    ip_addresses: Optional[List[str]] = None,
) -> List[str]:
    """
    Main reporting function. Compiles scan metadata, calculates threat KPIs,
    and writes timestamped reports in requested formats (JSON, HTML, Markdown).
    Fixes the prior duplicate function bug and hardcoded filename overwrite.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = current_timestamp()
    safe_target = _sanitize_filename(target)

    # Compile structured data object
    report_data = {
        "target": target,
        "ip": ip,
        "ip_addresses": ip_addresses or ([ip] if ip else []),
        "alive": alive,
        "scan_time": timestamp,
        "metadata": metadata or {
            "scanner_version": "Reconnoiter 2.0.0",
            "scan_start_time": timestamp,
            "scan_duration_seconds": 0,
        },
        "dns_records": dns_records or {},
        "subdomains": subdomains or {},
        "zone_transfer": zone_transfer or {},
        "os_detection": os_info or [],
        "services": findings,
    }

    # Enrich with summary counters and remediations
    summary = _compute_summary(report_data)
    report_data["summary"] = summary
    report_data["remediations"] = _generate_remediations(report_data, summary)

    # Determine requested formats
    selected_formats = formats or ["json"]
    normalized_formats = set()
    for fmt in selected_formats:
        for sub_fmt in fmt.lower().split(","):
            cleaned = sub_fmt.strip()
            if cleaned:
                normalized_formats.add(cleaned)

    generated_files: List[str] = []
    base_timestamp = timestamp.replace(":", "-")

    for fmt in normalized_formats:
        if fmt == "json":
            if output_path and output_path.endswith(".json"):
                path = output_path
            elif output_path and "." not in os.path.basename(output_path):
                path = f"{output_path}.json"
            else:
                path = os.path.join(REPORT_DIR, f"{safe_target}_{base_timestamp}.json")

            with open(path, "w", encoding="utf-8") as f:
                f.write(generate_json_report(report_data))
            generated_files.append(path)
            print(f"[+] JSON report written to {path}")

        elif fmt == "html":
            if output_path and output_path.endswith(".html"):
                path = output_path
            elif output_path and "." not in os.path.basename(output_path):
                path = f"{output_path}.html"
            else:
                path = os.path.join(REPORT_DIR, f"{safe_target}_{base_timestamp}.html")

            with open(path, "w", encoding="utf-8") as f:
                f.write(generate_html_report(report_data))
            generated_files.append(path)
            print(f"[+] HTML report written to {path}")

        elif fmt in ("md", "markdown"):
            if output_path and (output_path.endswith(".md") or output_path.endswith(".markdown")):
                path = output_path
            elif output_path and "." not in os.path.basename(output_path):
                path = f"{output_path}.md"
            else:
                path = os.path.join(REPORT_DIR, f"{safe_target}_{base_timestamp}.md")

            with open(path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_report(report_data))
            generated_files.append(path)
            print(f"[+] Markdown report written to {path}")

    return generated_files
