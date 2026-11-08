import socket
import unittest
from unittest.mock import MagicMock, patch

from dns_enum import (
    enumerate_dns,
    enumerate_subdomains,
    reverse_dns,
    test_zone_transfer,
)


class TestDNSEnum(unittest.TestCase):

    @patch("dns.resolver.resolve")
    def test_enumerate_dns(self, mock_resolve):
        mock_a = MagicMock()
        mock_a.to_text.return_value = "93.184.215.14"

        def side_effect(domain, rtype, **kwargs):
            if rtype == "A":
                return [mock_a]
            raise Exception("No record")

        mock_resolve.side_effect = side_effect

        records = enumerate_dns("example.com")
        self.assertIn("A", records)
        self.assertEqual(records["A"], ["93.184.215.14"])
        self.assertEqual(records["MX"], [])

    @patch("socket.gethostbyaddr")
    def test_reverse_dns(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        ptr = reverse_dns("8.8.8.8")
        self.assertEqual(ptr, "dns.google")

    @patch("dns.resolver.resolve")
    @patch("dns.query.xfr")
    @patch("dns.zone.from_xfr")
    @patch("socket.getaddrinfo")
    def test_zone_transfer_vulnerable(self, mock_addr, mock_from_xfr, mock_xfr, mock_resolve):
        ns_mock = MagicMock()
        ns_mock.to_text.return_value = "ns1.example.com."
        mock_resolve.return_value = [ns_mock]

        mock_addr.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.53", 53))
        ]

        zone_mock = MagicMock()
        node_mock = MagicMock()
        node_mock.to_text.return_value = "A 192.168.1.100"
        zone_mock.nodes = {"internal": node_mock}
        mock_from_xfr.return_value = zone_mock

        res = test_zone_transfer("example.com")
        self.assertTrue(res["vulnerable"])
        self.assertIn("ns1.example.com", res["vulnerable_nameservers"])
        self.assertTrue(len(res["leaked_records"]) > 0)

    @patch("dns.resolver.resolve")
    def test_zone_transfer_secure(self, mock_resolve):
        # NS resolution fails or AXFR raises exception
        mock_resolve.side_effect = Exception("Refused")
        res = test_zone_transfer("example.com")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["vulnerable_nameservers"], [])

    @patch("dns_enum._query_crtsh")
    @patch("dns_enum._resolve_subdomain")
    def test_enumerate_subdomains(self, mock_resolve_sub, mock_crtsh):
        mock_crtsh.return_value = {"api.example.com"}
        mock_resolve_sub.side_effect = lambda sub: ["10.0.0.1"] if sub == "api.example.com" else []

        subs = enumerate_subdomains("example.com", use_crtsh=True, wordlist=["api", "invalid"])
        self.assertIn("api.example.com", subs)
        self.assertEqual(subs["api.example.com"], ["10.0.0.1"])

    @patch("dns_enum._resolve_subdomain")
    def test_wildcard_dns_filtering(self, mock_resolve_sub):
        # Everything resolves to the wildcard IP 192.168.1.99
        mock_resolve_sub.side_effect = lambda sub: ["192.168.1.99"]
        subs = enumerate_subdomains("wildcard-test.com", use_crtsh=False, wordlist=["dev", "mail"])
        # Because all dictionary candidates match the wildcard IP, they should be filtered out
        self.assertEqual(subs, {})


if __name__ == "__main__":
    unittest.main()

