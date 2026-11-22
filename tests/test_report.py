import json
import os
import tempfile
import unittest

from report import (
    _compute_summary,
    _generate_remediations,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    write_report,
)


class TestReport(unittest.TestCase):

    def setUp(self):
        self.sample_findings = [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
                "banner": "HTTP/1.1 200 OK | Server: Apache/2.4.49",
                "cves": [
                    {
                        "id": "CVE-2021-41773",
                        "severity": "CRITICAL",
                        "cvss": 9.8,
                        "epss": 0.95,
                        "cisa_kev": True,
                    },
                    {
                        "id": "CVE-2021-42013",
                        "severity": "CRITICAL",
                        "cvss": 9.8,
                        "epss": 0.92,
                        "cisa_kev": True,
                    },
                ],
            },
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.9p1",
                "banner": "SSH-2.0-OpenSSH_8.9p1",
                "cves": [],
            },
        ]
        self.sample_report_data = {
            "target": "example.com",
            "ip": "93.184.215.14",
            "alive": True,
            "services": self.sample_findings,
            "metadata": {
                "scanner_version": "Sentrix 2.1.0",
                "scan_duration_seconds": 4.52,
                "command_line_args": "example.com -p 22,80",
            },
            "subdomains": {"api.example.com": ["93.184.215.15"]},
            "zone_transfer": {"vulnerable": False},
        }

    def test_compute_summary(self):
        summary = _compute_summary(self.sample_report_data)
        self.assertEqual(summary["total_services"], 2)
        self.assertEqual(summary["total_cves"], 2)
        self.assertEqual(summary["critical_cves"], 2)
        self.assertEqual(summary["cisa_kev_cves"], 2)
        self.assertEqual(summary["high_epss_cves"], 2)

    def test_compute_summary_worst_case_outcomes(self):
        # 1. 0 CVEs (confirmed clean)
        clean_data = {
            "services": [
                {"port": 80, "cve_status": "clean", "cves": []},
                {"port": 443, "cve_status": "clean", "cves": []},
            ]
        }
        s1 = _compute_summary(clean_data)
        self.assertEqual(s1["cve_summary_text"], "0 CVEs (confirmed clean)")

        # 2. 0 CVEs (no CPE match)
        no_cpe_data = {
            "services": [
                {"port": 80, "cve_status": "clean", "cves": []},
                {"port": 8080, "cve_status": "no_cpe", "cves": []},
            ]
        }
        s2 = _compute_summary(no_cpe_data)
        self.assertEqual(s2["cve_summary_text"], "0 CVEs (no CPE match)")

        # 3. 0 CVEs (lookup failed - N/N services unassessed) - worst case dominates
        failed_data = {
            "services": [
                {"port": 80, "cve_status": "clean", "cves": []},
                {"port": 8080, "cve_status": "no_cpe", "cves": []},
                {"port": 443, "cve_status": "failed", "cves": []},
            ]
        }
        s3 = _compute_summary(failed_data)
        self.assertEqual(s3["cve_summary_text"], "0 CVEs (lookup failed — 1/3 services unassessed)")

        # 4. Total CVEs > 0 with partial failure
        vuln_with_failed_data = {
            "services": [
                {"port": 80, "cve_status": "matched", "cves": [{"id": "CVE-2023-1", "severity": "CRITICAL"}]},
                {"port": 443, "cve_status": "failed", "cves": []},
            ]
        }
        s4 = _compute_summary(vuln_with_failed_data)
        self.assertIn("1 (Critical: 1) — ⚠️ 1/2 service lookups failed", s4["cve_summary_text"])

        # 5. No open services
        empty_data = {"services": []}
        s5 = _compute_summary(empty_data)
        self.assertEqual(s5["cve_summary_text"], "0 (No open services)")

    def test_generate_remediations(self):
        summary = _compute_summary(self.sample_report_data)
        remediations = _generate_remediations(self.sample_report_data, summary)
        titles = [r["title"] for r in remediations]
        self.assertIn("Immediate Patching of CISA KEV Vulnerabilities", titles)

    def test_generate_json_report(self):
        json_str = generate_json_report(self.sample_report_data)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["target"], "example.com")
        self.assertEqual(len(parsed["services"]), 2)

    def test_generate_html_report(self):
        self.sample_report_data["summary"] = _compute_summary(self.sample_report_data)
        self.sample_report_data["remediations"] = _generate_remediations(
            self.sample_report_data, self.sample_report_data["summary"]
        )
        html = generate_html_report(self.sample_report_data)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CVE-2021-41773", html)
        self.assertIn("EXPLOITED IN WILD", html)
        self.assertIn("Apache httpd", html)

    def test_generate_markdown_report(self):
        self.sample_report_data["summary"] = _compute_summary(self.sample_report_data)
        self.sample_report_data["remediations"] = _generate_remediations(
            self.sample_report_data, self.sample_report_data["summary"]
        )
        md = generate_markdown_report(self.sample_report_data)
        self.assertIn("# Sentrix Security Assessment Report: example.com", md)
        self.assertIn("CVE-2021-41773", md)
        self.assertIn("Open Services & Banner Intelligence", md)

    def test_write_report_multi_format(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_path = os.path.join(tmp_dir, "test_output")
            files = write_report(
                target="test.local",
                ip="192.168.1.50",
                findings=self.sample_findings,
                output_path=base_path,
                formats=["json", "html", "markdown"],
            )
            self.assertEqual(len(files), 3)
            for f in files:
                self.assertTrue(os.path.exists(f))
                self.assertGreater(os.path.getsize(f), 0)


if __name__ == "__main__":
    unittest.main()

