import os
import socket
import tempfile
import unittest
from unittest.mock import patch

from resolver import (
    expand_cidr,
    expand_ip_range,
    is_ip_address,
    parse_target_specifier,
    parse_targets_file,
    resolve,
    resolve_all_targets,
)


class TestResolver(unittest.TestCase):

    def test_is_ip_address(self):
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("2606:2800:21f:cb07:6820:80da:af6b:8b2c"))
        self.assertFalse(is_ip_address("example.com"))
        self.assertFalse(is_ip_address("invalid_ip"))

    @patch("socket.getaddrinfo")
    def test_resolve_ipv4_and_ipv6(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 0, 0, 0)),
        ]
        results = resolve("example.com")
        self.assertIn("93.184.215.14", results)
        self.assertIn("2606:2800:21f:cb07:6820:80da:af6b:8b2c", results)
        self.assertEqual(len(results), 2)

    def test_resolve_direct_ip(self):
        self.assertEqual(resolve("10.0.0.1"), ["10.0.0.1"])
        self.assertEqual(resolve("::1"), ["::1"])

    def test_expand_cidr(self):
        ips = expand_cidr("192.168.1.0/30")
        self.assertEqual(len(ips), 2)
        self.assertIn("192.168.1.1", ips)
        self.assertIn("192.168.1.2", ips)

        single = expand_cidr("10.0.0.5/32")
        self.assertEqual(single, ["10.0.0.5"])

    def test_expand_ip_range(self):
        ips = expand_ip_range("192.168.1.1-192.168.1.4")
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"])

        short_range = expand_ip_range("10.0.0.8-10")
        self.assertEqual(short_range, ["10.0.0.8", "10.0.0.9", "10.0.0.10"])

    def test_parse_target_specifier(self):
        cidr_res = parse_target_specifier("192.168.1.0/30")
        self.assertEqual(len(cidr_res), 2)

        range_res = parse_target_specifier("10.0.0.1-3")
        self.assertEqual(range_res, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        host_res = parse_target_specifier("scanme.nmap.org")
        self.assertEqual(host_res, ["scanme.nmap.org"])

    def test_parse_targets_file(self):
        content = """# Comment line
192.168.1.1
example.com

# Another comment
10.0.0.1-2
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            targets = parse_targets_file(temp_path)
            self.assertIn("192.168.1.1", targets)
            self.assertIn("example.com", targets)
            self.assertIn("10.0.0.1", targets)
            self.assertIn("10.0.0.2", targets)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @patch("resolver.resolve")
    def test_resolve_all_targets(self, mock_resolve):
        mock_resolve.side_effect = lambda t: [f"192.168.1.{t[-1]}"] if t[-1].isdigit() else ["93.184.215.14"]
        res = resolve_all_targets(["example.com", "10.0.0.1-2"])
        self.assertIn("example.com", res)
        self.assertIn("10.0.0.1", res)
        self.assertIn("10.0.0.2", res)


if __name__ == "__main__":
    unittest.main()

