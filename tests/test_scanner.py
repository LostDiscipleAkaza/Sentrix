import unittest
from unittest.mock import MagicMock, patch

from scanner import _parse_ports_list, _socket_probe_port, infer_cpe_from_banner, scan, socket_scan


class TestScanner(unittest.TestCase):

    def test_infer_cpe_from_banner(self):
        cpes, prod, ver = infer_cpe_from_banner("HTTP/1.1 200 OK | Server: Apache/2.4.49 (Ubuntu)")
        self.assertEqual(cpes, ["cpe:/a:apache:http_server:2.4.49"])
        self.assertEqual(prod, "Apache httpd")
        self.assertEqual(ver, "2.4.49")

        cpes, prod, ver = infer_cpe_from_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertEqual(cpes, ["cpe:/a:openbsd:openssh:8.9p1"])
        self.assertEqual(prod, "OpenSSH")
        self.assertEqual(ver, "8.9p1")

        cpes, prod, ver = infer_cpe_from_banner("Server: nginx/1.18.0")
        self.assertEqual(cpes, ["cpe:/a:igor_sysoev:nginx:1.18.0"])
        self.assertEqual(prod, "nginx")
        self.assertEqual(ver, "1.18.0")

    def test_parse_ports_list(self):
        # Default top-200
        top = _parse_ports_list("top-200")
        self.assertIn(80, top)
        self.assertIn(443, top)

        # Comma separated
        ports = _parse_ports_list("80,443,8080")
        self.assertEqual(ports, [80, 443, 8080])

        # Range
        range_ports = _parse_ports_list("20-23")
        self.assertEqual(range_ports, [20, 21, 22, 23])

        # Mixed
        mixed = _parse_ports_list("80,8080-8082,invalid")
        self.assertEqual(mixed, [80, 8080, 8081, 8082])

    @patch("socket.socket")
    def test_socket_probe_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        self.assertTrue(_socket_probe_port("127.0.0.1", 80))

        mock_sock.connect_ex.return_value = 111
        self.assertFalse(_socket_probe_port("127.0.0.1", 80))

    @patch("scanner._socket_probe_port")
    @patch("scanner.grab_banners_concurrent")
    def test_socket_scan(self, mock_grab, mock_probe):
        mock_probe.side_effect = lambda ip, p: p in (80, 443)
        mock_grab.return_value = {
            80: "HTTP/1.1 200 OK | Server: nginx",
            443: "HTTP/1.1 200 OK | Server: cloudflare",
        }

        findings, os_info = socket_scan("127.0.0.1", "80,443,22")
        self.assertEqual(len(findings), 2)
        ports = [f["port"] for f in findings]
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertEqual(findings[0]["service"], "http")
        self.assertEqual(findings[1]["service"], "https")

    @patch("scanner._HAS_NMAP", True)
    @patch("scanner.grab_banners_concurrent")
    def test_scan_with_nmap_mock(self, mock_grab):
        mock_nmap = MagicMock()
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner.__getitem__.return_value = {
            "osmatch": [{"name": "Linux 5.4", "accuracy": "98"}],
            "tcp": {
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "extrainfo": "",
                    "cpe": "cpe:/a:apache:http_server:2.4.49",
                }
            },
        }
        mock_nmap.PortScanner.return_value = mock_scanner
        mock_grab.return_value = {80: "Apache 2.4.49"}

        with patch("scanner.nmap", mock_nmap):
            findings, os_info = scan("192.168.1.1", port_spec="80")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["port"], 80)
            self.assertEqual(findings[0]["service"], "http")
            self.assertEqual(findings[0]["product"], "Apache httpd")
            self.assertEqual(findings[0]["banner"], "Apache 2.4.49")
            self.assertEqual(len(os_info), 1)
            self.assertEqual(os_info[0]["name"], "Linux 5.4")

    @patch("scanner._HAS_NMAP", False)
    @patch("scanner.socket_scan")
    def test_scan_fallback_to_socket(self, mock_socket_scan):
        mock_socket_scan.return_value = ([{"port": 80}], [])
        findings, os_info = scan("127.0.0.1", port_spec="80")
        mock_socket_scan.assert_called_once()
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
