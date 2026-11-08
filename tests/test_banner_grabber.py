import socket
import unittest
from unittest.mock import MagicMock, patch

from banner_grabber import (
    _create_ssl_context,
    _probe_generic,
    _probe_http,
    grab_banner,
    grab_banners_concurrent,
)


class TestBannerGrabber(unittest.TestCase):

    def test_probe_http_with_server_header(self):
        mock_sock = MagicMock()
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n\r\n"
        )
        mock_sock.recv.return_value = http_response

        banner = _probe_http(mock_sock, "example.com")
        self.assertIn("HTTP/1.1 200 OK", banner)
        self.assertIn("Server: nginx/1.24.0 (Ubuntu)", banner)

    def test_probe_generic_immediate(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

        banner = _probe_generic(mock_sock)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

    def test_probe_generic_on_crlf(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [socket.timeout(), b"220 FTP Server ready.\r\n"]

        banner = _probe_generic(mock_sock)
        self.assertEqual(banner, "220 FTP Server ready.")

    @patch("socket.socket")
    def test_grab_banner_plain_http(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n"
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        mock_socket_cls.return_value = mock_sock

        banner = grab_banner("127.0.0.1", 80, timeout=1.0)
        self.assertIn("Apache/2.4.52", banner)

    @patch("banner_grabber._create_ssl_context")
    @patch("socket.socket")
    def test_grab_banner_tls_port(self, mock_socket_cls, mock_ssl_ctx_fn):
        raw_sock = MagicMock()
        tls_sock = MagicMock()
        tls_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Cloudflare\r\n\r\n"

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = tls_sock
        mock_ssl_ctx_fn.return_value = mock_ctx
        mock_socket_cls.return_value = raw_sock

        banner = grab_banner("1.1.1.1", 443, timeout=1.0, hostname="cloudflare.com")
        self.assertIn("Cloudflare", banner)
        mock_ctx.wrap_socket.assert_called_once()

    @patch("banner_grabber.grab_banner")
    def test_grab_banners_concurrent(self, mock_grab):
        mock_grab.side_effect = lambda ip, port, *args, **kwargs: f"Banner on {port}"
        ports = [22, 80, 443]
        results = grab_banners_concurrent("10.0.0.1", ports)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[22], "Banner on 22")
        self.assertEqual(results[80], "Banner on 80")
        self.assertEqual(results[443], "Banner on 443")


if __name__ == "__main__":
    unittest.main()
