import ssl
import unittest
from unittest.mock import MagicMock, patch

from fingerprint import (
    audit_security_headers,
    detect_waf_cdn,
    fingerprint_web_technologies,
    inspect_tls_certificate,
    perform_deep_http_fingerprint,
)


class TestFingerprint(unittest.TestCase):

    def test_detect_waf_cdn(self):
        # Cloudflare via Server
        self.assertEqual(detect_waf_cdn({"Server": "cloudflare"}), "Cloudflare")
        # Cloudflare via cf-ray
        self.assertEqual(detect_waf_cdn({"cf-ray": "84821a7cd9b2-IAD"}), "Cloudflare")
        # AWS CloudFront via Via
        self.assertEqual(detect_waf_cdn({"Via": "1.1 cloudfront.net"}), "AWS CloudFront")
        # Akamai
        self.assertEqual(detect_waf_cdn({"Server": "AkamaiGHost"}), "Akamai")
        # Fastly
        self.assertEqual(detect_waf_cdn({"x-fastly-request-id": "abc123"}), "Fastly")
        # Imperva
        self.assertEqual(detect_waf_cdn({"x-iinfo": "xyz"}), "Imperva / Incapsula")
        # Azure Front Door
        self.assertEqual(detect_waf_cdn({"x-azure-ref": "0Abc"}), "Azure Front Door")
        # Sucuri
        self.assertEqual(detect_waf_cdn({"x-sucuri-id": "12345"}), "Sucuri")
        # F5 BIG-IP
        self.assertEqual(detect_waf_cdn({"Set-Cookie": "BIGipServer_pool=123"}), "F5 BIG-IP")
        # No WAF detected
        self.assertIsNone(detect_waf_cdn({"Server": "nginx/1.18.0", "Content-Type": "text/html"}))

    def test_fingerprint_web_technologies_headers_and_cookies(self):
        headers = {
            "Server": "nginx/1.21.6",
            "X-Powered-By": "PHP/8.1.2",
            "Set-Cookie": "PHPSESSID=abcdef123456; path=/",
        }
        techs = fingerprint_web_technologies(headers, body="")
        self.assertIn("nginx 1.21.6", techs)
        self.assertIn("PHP/8.1.2", techs)
        self.assertIn("PHP", techs)

        # Java / Express / Django cookies
        java_techs = fingerprint_web_technologies({"Set-Cookie": "JSESSIONID=xyz"})
        self.assertIn("Java (JSP / Servlet)", java_techs)

        django_techs = fingerprint_web_technologies({"Set-Cookie": "csrftoken=abc; django_language=en"})
        self.assertIn("Django", django_techs)

        node_techs = fingerprint_web_technologies({"Set-Cookie": "connect.sid=s%3A123"})
        self.assertIn("Node.js (Express Session)", node_techs)

    def test_fingerprint_web_technologies_body(self):
        body_wp = '<link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">'
        techs_wp = fingerprint_web_technologies({}, body=body_wp)
        self.assertIn("WordPress CMS", techs_wp)

        body_next = '<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>'
        techs_next = fingerprint_web_technologies({}, body=body_next)
        self.assertIn("Next.js (React)", techs_next)

        body_vue = '<div id="app" data-v-123456></div>'
        techs_vue = fingerprint_web_technologies({}, body=body_vue)
        self.assertIn("Vue.js", techs_vue)

        body_angular = '<app-root ng-version="15.2.0"></app-root>'
        techs_angular = fingerprint_web_technologies({}, body=body_angular)
        self.assertIn("Angular", techs_angular)

    def test_audit_security_headers(self):
        # All 6 recommended headers present
        secure_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        audit = audit_security_headers(secure_headers)
        self.assertEqual(audit["score"], "6/6")
        self.assertEqual(audit["grade"], "A")
        self.assertEqual(len(audit["missing"]), 0)
        self.assertIn("Strict-Transport-Security (HSTS)", audit["present"])

        # Insecure / Missing headers
        insecure_headers = {"Server": "Apache/2.4.41"}
        audit_insecure = audit_security_headers(insecure_headers)
        self.assertEqual(audit_insecure["score"], "0/6")
        self.assertEqual(audit_insecure["grade"], "F")
        self.assertEqual(len(audit_insecure["missing"]), 6)
        # Check remediation field is present
        self.assertTrue(any("HSTS" in item["header"] for item in audit_insecure["missing"]))

    @patch("fingerprint.socket.socket")
    @patch("fingerprint.ssl.create_default_context")
    def test_inspect_tls_certificate_valid(self, mock_ssl_ctx, mock_socket_cls):
        mock_raw = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_raw

        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.side_effect = [
            b"fake-der-bytes",  # binary_form=True for permissive
            {                   # dict form for verified
                "subject": ((("commonName", "example.com"),),),
                "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
                "issuer": ((("organizationName", "DigiCert Inc"),),),
                "notAfter": "Jul 05 23:59:59 2030 GMT",
            },
        ]

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl_ctx.return_value = mock_ctx

        cert_info = inspect_tls_certificate("93.184.216.34", 443, hostname="example.com")
        self.assertIsNotNone(cert_info)
        self.assertEqual(cert_info["tls_version"], "TLSv1.3")
        self.assertEqual(cert_info["subject_cn"], "example.com")
        self.assertEqual(cert_info["sans"], ["example.com", "www.example.com"])
        self.assertEqual(cert_info["issuer"], "DigiCert Inc")
        self.assertFalse(cert_info["is_self_signed"])
        self.assertFalse(cert_info["is_expired"])
        self.assertGreater(cert_info["days_until_expiry"], 0)

    @patch("fingerprint.socket.socket")
    def test_perform_deep_http_fingerprint_plain(self, mock_socket_cls):
        mock_sock = MagicMock()
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: cloudflare\r\n"
            b"cf-ray: 12345\r\n"
            b"X-Powered-By: PHP/8.2\r\n"
            b"X-Frame-Options: SAMEORIGIN\r\n"
            b"\r\n"
            b"<html><head><title>My Test Site</title></head><body><div class=\"wp-content\">Hello</div></body></html>"
        )
        mock_sock.recv.side_effect = [http_response, b""]
        mock_sock.__enter__.return_value = mock_sock
        mock_socket_cls.return_value = mock_sock

        fp = perform_deep_http_fingerprint("1.2.3.4", 80, hostname="example.com")
        self.assertEqual(fp["status_line"], "HTTP/1.1 200 OK")
        self.assertEqual(fp["title"], "My Test Site")
        self.assertEqual(fp["waf_cdn"], "Cloudflare")
        self.assertIn("PHP/8.2", fp["technologies"])
        self.assertIn("WordPress CMS", fp["technologies"])
        self.assertEqual(fp["security_headers"]["grade"], "F")  # Only 1 header present (X-Frame-Options)


if __name__ == "__main__":
    unittest.main()
