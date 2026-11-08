import unittest
from unittest.mock import MagicMock, patch

from host_discovery import icmp_ping, is_host_alive, tcp_ping, tcp_ping_multi


class TestHostDiscovery(unittest.TestCase):

    @patch("host_discovery.platform.system", return_value="Linux")
    @patch("host_discovery.subprocess.run")
    def test_icmp_ping_success(self, mock_run, mock_sys):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        self.assertTrue(icmp_ping("192.168.1.1"))

    @patch("host_discovery.platform.system", return_value="Linux")
    @patch("host_discovery.subprocess.run")
    def test_icmp_ping_failure(self, mock_run, mock_sys):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc
        self.assertFalse(icmp_ping("192.168.1.1"))

    @patch("socket.socket")
    def test_tcp_ping_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        self.assertTrue(tcp_ping("192.168.1.1", 443))

    @patch("socket.socket")
    def test_tcp_ping_failure(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        self.assertFalse(tcp_ping("192.168.1.1", 443))

    @patch("host_discovery.tcp_ping")
    def test_tcp_ping_multi(self, mock_tcp):
        mock_tcp.side_effect = lambda ip, port, timeout: port == 443
        self.assertTrue(tcp_ping_multi("192.168.1.1", [80, 443, 22]))

    @patch("host_discovery.icmp_ping")
    @patch("host_discovery.tcp_ping_multi")
    def test_is_host_alive_hybrid(self, mock_tcp_multi, mock_icmp):
        # Case 1: ICMP succeeds immediately
        mock_icmp.return_value = True
        self.assertTrue(is_host_alive("192.168.1.1"))
        mock_tcp_multi.assert_not_called()

        # Case 2: ICMP blocked, but TCP connect succeeds (modern firewall scenario)
        mock_icmp.return_value = False
        mock_tcp_multi.return_value = True
        self.assertTrue(is_host_alive("192.168.1.1"))

        # Case 3: Both ICMP and TCP probe fail
        mock_icmp.return_value = False
        mock_tcp_multi.return_value = False
        self.assertFalse(is_host_alive("192.168.1.1"))


if __name__ == "__main__":
    unittest.main()
