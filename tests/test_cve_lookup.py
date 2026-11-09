import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import cve_lookup
from cve_lookup import (
    cpe22_to_cpe23,
    cpe22_vendor_product,
    enrich_cves,
    get_cached_cpe,
    get_cached_epss,
    init_cache_db,
    lookup_cves,
    set_cached_cpe,
    set_cached_epss,
)


class TestCVELookup(unittest.TestCase):

    def setUp(self):
        cve_lookup._MIN_INTERVAL = 0.0
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        init_cache_db(self.db_path)

    def tearDown(self):
        cve_lookup._cisa_kev_memory_cache = None
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_cpe22_to_cpe23(self):
        cpe22 = "cpe:/a:apache:http_server:2.4.50"
        cpe23 = cpe22_to_cpe23(cpe22)
        self.assertEqual(cpe23, "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*")

        # Incomplete / wildcard
        cpe_wild = "cpe:/a:nginx:nginx"
        self.assertEqual(cpe22_to_cpe23(cpe_wild), "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")

        # Invalid
        self.assertIsNone(cpe22_to_cpe23("invalid_cpe_string"))

    def test_cpe22_vendor_product(self):
        vendor, product = cpe22_vendor_product("cpe:/a:igor_sysoev:nginx:1.18.0")
        self.assertEqual(vendor, "igor_sysoev")
        self.assertEqual(product, "nginx")

        v_none, p_none = cpe22_vendor_product("not_a_cpe")
        self.assertIsNone(v_none)
        self.assertIsNone(p_none)

    def test_sqlite_cpe_cache_ttl(self):
        cpe = "cpe:/a:test:product:1.0"
        payload = {
            "status": "matched",
            "source": "nvd",
            "reason": None,
            "cves": [{"id": "CVE-2023-0001", "cvss": 9.8, "severity": "CRITICAL"}],
        }

        # Store in cache
        set_cached_cpe(cpe, payload, db_path=self.db_path)

        # Retrieve immediately (within 7-day TTL)
        cached = get_cached_cpe(cpe, ttl_seconds=600, db_path=self.db_path)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["status"], "matched")
        self.assertEqual(cached["cves"][0]["id"], "CVE-2023-0001")

        # Test expiration with ttl_seconds = 0
        time.sleep(0.01)
        expired = get_cached_cpe(cpe, ttl_seconds=0, db_path=self.db_path)
        self.assertIsNone(expired)

    def test_sqlite_epss_cache(self):
        epss_data = {
            "CVE-2021-44228": {"epss": 0.975, "percentile": 0.999},
            "CVE-2023-1234": {"epss": 0.05, "percentile": 0.50},
        }
        set_cached_epss(epss_data, db_path=self.db_path)

        loaded = get_cached_epss(["CVE-2021-44228", "CVE-2023-1234"], db_path=self.db_path)
        self.assertEqual(len(loaded), 2)
        self.assertAlmostEqual(loaded["CVE-2021-44228"]["epss"], 0.975)

    @patch("cve_lookup.load_cisa_kev_catalog")
    @patch("cve_lookup.fetch_epss_scores")
    def test_enrich_cves_prioritizes_kev(self, mock_epss, mock_kev):
        mock_kev.return_value = {"CVE-2021-44228"}
        mock_epss.return_value = {
            "CVE-2021-44228": {"epss": 0.95, "percentile": 0.99},
            "CVE-2023-9999": {"epss": 0.80, "percentile": 0.90},
        }

        raw_cves = [
            {"id": "CVE-2023-9999", "cvss": 10.0, "severity": "CRITICAL"},
            {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL"},
        ]

        enriched = enrich_cves(raw_cves)
        self.assertEqual(len(enriched), 2)
        # KEV CVE should be ranked first
        self.assertEqual(enriched[0]["id"], "CVE-2021-44228")
        self.assertTrue(enriched[0]["cisa_kev"])
        self.assertFalse(enriched[1]["cisa_kev"])
        self.assertEqual(enriched[0]["epss"], 0.95)

    @patch("cve_lookup.requests.get")
    def test_lookup_by_cpe_uses_cpe_name_and_filters_unrelated(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Return a payload that contains 1 valid nginx CVE and 1 unrelated ping of death CVE
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-1999-0128",
                        "descriptions": [{"value": "Buffer overflow in ping/icmp handling."}],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2021-23017",
                        "descriptions": [{"value": "A security issue in nginx 1.18.0 DNS resolver allows memory overwrite."}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}]},
                    }
                },
            ]
        }
        mock_get.return_value = mock_resp

        # 1. Test exact version CPE uses cpeName param
        res = cve_lookup.lookup_by_cpe("cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*")
        args, kwargs = mock_get.call_args
        self.assertIn("cpeName", kwargs["params"])
        self.assertNotIn("virtualMatchString", kwargs["params"])

        # 2. Test that CVE-1999-0128 was rejected as false positive and CVE-2021-23017 was kept
        cve_ids = [c["id"] for c in res["cves"]]
        self.assertNotIn("CVE-1999-0128", cve_ids)
        self.assertIn("CVE-2021-23017", cve_ids)

        # 3. Test wildcard version uses virtualMatchString param
        cve_lookup.lookup_by_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        args, kwargs = mock_get.call_args
        self.assertIn("virtualMatchString", kwargs["params"])

    @patch("cve_lookup.lookup_by_cpe")
    @patch("cve_lookup.enrich_cves")
    def test_lookup_cves_flow(self, mock_enrich, mock_cpe):
        mock_cpe.return_value = {
            "status": "matched",
            "source": "nvd",
            "cves": [{"id": "CVE-2022-1234", "cvss": 7.5, "severity": "HIGH"}],
        }
        mock_enrich.side_effect = lambda cves: cves

        res = lookup_cves("cpe:/a:apache:http_server:2.4.49", bypass_cache=True)
        self.assertEqual(res["status"], "matched")
        self.assertEqual(len(res["cves"]), 1)
        self.assertEqual(res["cves"][0]["id"], "CVE-2022-1234")


if __name__ == "__main__":
    unittest.main()
