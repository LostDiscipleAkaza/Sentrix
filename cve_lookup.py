"""
Vulnerability intelligence with local SQLite caching, NVD v2.0 lookup,
CIRCL fallback, CISA KEV (Known Exploited Vulnerabilities), and EPSS scoring.
"""

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import requests

logger = logging.getLogger("reconnoiter")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_URL = "https://vulnerability.circl.lu/api/search"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

CACHE_DB_PATH = os.environ.get("RECON_CACHE_DB", "cve_cache.db")
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60  # 7-day TTL

VENDOR_ALIASES = {
    ("igor_sysoev", "nginx"): "f5",
}

API_KEY = os.environ.get("NVD_API_KEY")
_MIN_INTERVAL = 0.7 if API_KEY else 6.5
_throttle_lock = threading.Lock()
_last_request_time = 0.0

_cisa_kev_memory_cache: Optional[Set[str]] = None
_db_lock = threading.Lock()


# ---------------------------------------------------------------------------
# SQLite Cache Layer
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _open_db(db_path: str = CACHE_DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that opens, commits, and explicitly closes SQLite connection."""
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_cache_db(db_path: str = CACHE_DB_PATH) -> None:
    """Initializes SQLite database tables for CPE lookups, CISA KEV, and EPSS scores."""
    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cpe_cache (
                    cpe TEXT PRIMARY KEY,
                    status TEXT,
                    source TEXT,
                    reason TEXT,
                    cves_json TEXT,
                    cached_at REAL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cisa_kev_cache (
                    cve_id TEXT PRIMARY KEY,
                    date_added TEXT,
                    cached_at REAL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS epss_cache (
                    cve_id TEXT PRIMARY KEY,
                    epss REAL,
                    percentile REAL,
                    cached_at REAL
                )
                """
            )


def get_cached_cpe(
    cpe: str, ttl_seconds: float = DEFAULT_TTL_SECONDS, db_path: str = CACHE_DB_PATH
) -> Optional[Dict[str, Any]]:
    """Retrieves a cached CVE lookup result if present and within TTL."""
    init_cache_db(db_path)
    now = time.time()
    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status, source, reason, cves_json, cached_at FROM cpe_cache WHERE cpe = ?",
                (cpe,),
            )
            row = cursor.fetchone()
            if row:
                status, source, reason, cves_json, cached_at = row
                if now - cached_at <= ttl_seconds:
                    try:
                        cves = json.loads(cves_json)
                        return {
                            "status": status,
                            "source": source,
                            "reason": reason,
                            "cves": cves,
                            "cached": True,
                        }
                    except json.JSONDecodeError:
                        return None
    return None


def set_cached_cpe(
    cpe: str, result: Dict[str, Any], db_path: str = CACHE_DB_PATH
) -> None:
    """Stores a CVE lookup result in the local SQLite cache."""
    # Don't cache error states for a full 7 days; only clean matches / unmatches
    if result.get("status") == "error":
        return

    init_cache_db(db_path)
    now = time.time()
    cves_json = json.dumps(result.get("cves", []))
    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO cpe_cache (cpe, status, source, reason, cves_json, cached_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    cpe,
                    result.get("status"),
                    result.get("source"),
                    result.get("reason"),
                    cves_json,
                    now,
                ),
            )


def get_cached_epss(
    cve_ids: List[str], ttl_seconds: float = DEFAULT_TTL_SECONDS, db_path: str = CACHE_DB_PATH
) -> Dict[str, Dict[str, float]]:
    """Retrieves cached EPSS scores for given CVE IDs that have not expired."""
    init_cache_db(db_path)
    now = time.time()
    results: Dict[str, Dict[str, float]] = {}
    if not cve_ids:
        return results

    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in cve_ids)
            cursor.execute(
                f"SELECT cve_id, epss, percentile, cached_at FROM epss_cache WHERE cve_id IN ({placeholders})",
                cve_ids,
            )
            for row in cursor.fetchall():
                cve_id, epss, percentile, cached_at = row
                if now - cached_at <= ttl_seconds:
                    results[cve_id] = {"epss": epss, "percentile": percentile}

    return results


def set_cached_epss(
    epss_data: Dict[str, Dict[str, float]], db_path: str = CACHE_DB_PATH
) -> None:
    """Saves EPSS scores into local SQLite cache."""
    if not epss_data:
        return
    init_cache_db(db_path)
    now = time.time()
    rows = [
        (cve_id, val.get("epss"), val.get("percentile"), now)
        for cve_id, val in epss_data.items()
    ]
    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                "INSERT OR REPLACE INTO epss_cache (cve_id, epss, percentile, cached_at) VALUES (?, ?, ?, ?)",
                rows,
            )


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities) Integration
# ---------------------------------------------------------------------------

def load_cisa_kev_catalog(
    ttl_seconds: float = DEFAULT_TTL_SECONDS, db_path: str = CACHE_DB_PATH
) -> Set[str]:
    """
    Loads CISA KEV catalog into memory. Uses local SQLite cache first.
    If empty or expired, downloads fresh catalog from CISA and updates SQLite.
    """
    global _cisa_kev_memory_cache
    if _cisa_kev_memory_cache is not None:
        return _cisa_kev_memory_cache

    init_cache_db(db_path)
    now = time.time()
    cached_kevs: Set[str] = set()

    with _db_lock:
        with _open_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MIN(cached_at) FROM cisa_kev_cache")
            min_row = cursor.fetchone()
            if min_row and min_row[0] is not None:
                oldest = min_row[0]
                if now - oldest <= ttl_seconds:
                    cursor.execute("SELECT cve_id FROM cisa_kev_cache")
                    cached_kevs = {r[0] for r in cursor.fetchall()}
                    _cisa_kev_memory_cache = cached_kevs
                    return _cisa_kev_memory_cache

    # Attempt download from CISA KEV feed
    try:
        r = requests.get(CISA_KEV_URL, timeout=10)
        if r.status_code == 200:
            data = r.json()
            vulnerabilities = data.get("vulnerabilities", [])
            kev_set = {v["cveID"] for v in vulnerabilities if "cveID" in v}
            rows_to_insert = [
                (v.get("cveID"), v.get("dateAdded", ""), now)
                for v in vulnerabilities
                if "cveID" in v
            ]
            with _db_lock:
                with _open_db(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM cisa_kev_cache")
                    cursor.executemany(
                        "INSERT OR REPLACE INTO cisa_kev_cache (cve_id, date_added, cached_at) VALUES (?, ?, ?)",
                        rows_to_insert,
                    )
            _cisa_kev_memory_cache = kev_set
            return _cisa_kev_memory_cache
    except Exception as e:
        logger.debug(f"Could not update CISA KEV feed: {e}")

    # Fallback to existing cached KEVs if fresh fetch failed
    _cisa_kev_memory_cache = cached_kevs
    return _cisa_kev_memory_cache
    return _cisa_kev_memory_cache


# ---------------------------------------------------------------------------
# EPSS (Exploit Prediction Scoring System) Integration
# ---------------------------------------------------------------------------

def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
    """
    Fetches EPSS probability and percentile for a list of CVEs.
    Leverages SQLite caching to minimize network overhead.
    """
    if not cve_ids:
        return {}

    # 1. Check local SQLite cache
    cached_scores = get_cached_epss(cve_ids)
    missing = [c for c in cve_ids if c not in cached_scores]

    if not missing:
        return cached_scores

    # 2. Query FIRST EPSS API for missing CVEs in chunks of 50
    fresh_scores: Dict[str, Dict[str, float]] = {}
    chunk_size = 50
    for i in range(0, len(missing), chunk_size):
        chunk = missing[i : i + chunk_size]
        try:
            r = requests.get(
                EPSS_URL, params={"cve": ",".join(chunk)}, timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    try:
                        epss_val = float(item.get("epss", 0.0))
                        pct_val = float(item.get("percentile", 0.0))
                        fresh_scores[cve_id] = {
                            "epss": epss_val,
                            "percentile": pct_val,
                        }
                    except (ValueError, TypeError):
                        continue
        except Exception as e:
            logger.debug(f"EPSS lookup error for {chunk}: {e}")

    if fresh_scores:
        set_cached_epss(fresh_scores)
        cached_scores.update(fresh_scores)

    return cached_scores


def enrich_cves(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enriches CVE entries with CISA KEV flags and EPSS probabilities.
    Prioritizes actively exploited vulnerabilities.
    """
    if not cves:
        return []

    cve_ids = [c["id"] for c in cves if "id" in c]
    kev_set = load_cisa_kev_catalog()
    epss_map = fetch_epss_scores(cve_ids)

    for c in cves:
        cve_id = c.get("id")
        c["cisa_kev"] = cve_id in kev_set
        c["is_known_exploited"] = c["cisa_kev"]

        epss_info = epss_map.get(cve_id, {})
        c["epss"] = epss_info.get("epss")
        c["epss_percentile"] = epss_info.get("percentile")

    # Sort: Actively exploited first, then highest EPSS, then highest CVSS
    def sort_key(item: Dict[str, Any]) -> Tuple[int, float, float]:
        kev_rank = 0 if item.get("cisa_kev") else 1
        epss_rank = -(item.get("epss") or 0.0)
        cvss_rank = -(item.get("cvss") or 0.0)
        return (kev_rank, epss_rank, cvss_rank)

    cves.sort(key=sort_key)
    return cves


# ---------------------------------------------------------------------------
# CPE Parsing & Transformation
# ---------------------------------------------------------------------------

def _throttle() -> None:
    """Block just long enough to stay safely under NVD's rate limit."""
    global _last_request_time
    with _throttle_lock:
        wait = _MIN_INTERVAL - (time.time() - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.time()


def _headers() -> Dict[str, str]:
    return {"apiKey": API_KEY} if API_KEY else {}


def cpe22_to_cpe23(cpe22: Any) -> Optional[str]:
    """
    Converts nmap's CPE 2.2 URI format into CPE 2.3 formatted string.
    Returns None if the input isn't a clean, valid CPE 2.2 string.
    """
    if isinstance(cpe22, list):
        cpe22 = cpe22[0] if cpe22 else ""

    if not cpe22 or not isinstance(cpe22, str) or not cpe22.startswith("cpe:/"):
        return None

    body = cpe22[len("cpe:/") :]
    parts = body.split(":")

    if len(parts) > 5:
        return None

    if not parts or parts[0] not in ("a", "o", "h"):
        return None

    while len(parts) < 5:
        parts.append("*")

    return "cpe:2.3:" + ":".join(parts) + ":*:*:*:*:*:*"


def cpe22_vendor_product(cpe22: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extracts (vendor, product) from an nmap CPE 2.2 string."""
    if isinstance(cpe22, list):
        cpe22 = cpe22[0] if cpe22 else ""

    if not cpe22 or not isinstance(cpe22, str) or not cpe22.startswith("cpe:/"):
        return None, None

    parts = cpe22[len("cpe:/") :].split(":")
    if len(parts) < 3:
        return None, None

    return (parts[1] or None), (parts[2] or None)


def _with_vendor(cpe23: str, vendor: str) -> str:
    """Returns cpe23 with its vendor field (position 3) replaced."""
    fields = cpe23.split(":")
    if len(fields) <= 3:
        return cpe23
    fields[3] = vendor
    return ":".join(fields)


def _parse_cve_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    severity, score = "UNKNOWN", None
    try:
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            severity, score = data.get("baseSeverity", "UNKNOWN"), data.get("baseScore")
        elif "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0]["cvssData"]
            severity, score = data.get("baseSeverity", "UNKNOWN"), data.get("baseScore")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            severity = m.get("baseSeverity", "UNKNOWN")
            score = m.get("cvssData", {}).get("baseScore")
    except (KeyError, IndexError, TypeError):
        pass
    return {"id": cve.get("id"), "severity": severity, "cvss": score}


# ---------------------------------------------------------------------------
# NVD & CIRCL Lookups
# ---------------------------------------------------------------------------

def lookup_by_cpe(cpe23: Optional[str]) -> Dict[str, Any]:
    """Looks up CVEs for an exact CPE 2.3 string via NVD."""
    if not cpe23:
        return {"status": "unmatched", "cves": [], "reason": "no_cpe_available"}

    fields = cpe23.split(":")
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    vendor = fields[3] if len(fields) > 3 else ""
    product = fields[4] if len(fields) > 4 else ""
    version = fields[5] if len(fields) > 5 else "*"

    is_version_wildcard = version in ("*", "-", "")
    # In NVD API 2.0:
    # Use cpeName when a specific version is provided (non-wildcard).
    # Use virtualMatchString only when version is wildcarded.
    param_name = "virtualMatchString" if is_version_wildcard else "cpeName"

    try:
        _throttle()
        r = requests.get(
            NVD_URL,
            params={param_name: cpe23, "resultsPerPage": 200},
            headers=_headers(),
            timeout=20,
        )
        if r.status_code == 429:
            return {"status": "error", "cves": [], "reason": "rate_limited"}
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException as e:
        return {"status": "error", "cves": [], "reason": f"request_failed: {e}"}
    except ValueError:
        return {"status": "error", "cves": [], "reason": "invalid_json_response"}

    seen = {}
    product_clean = product.lower().replace("_", "")
    vendor_clean = vendor.lower().replace("_", "")

    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})

        # Validation: Protect against NVD returning default unfiltered feed (e.g. Ping of Death from 1999)
        # Verify that either the CVE configurations or descriptions relate to the requested product/vendor
        if product_clean:
            descs = " ".join(d.get("value", "").lower() for d in cve_obj.get("descriptions", []))
            configs_str = json.dumps(cve_obj.get("configurations", [])).lower()
            if product_clean not in descs and product.lower() not in descs and product_clean not in configs_str:
                # If neither product nor vendor appears anywhere in the CVE record, reject as false positive
                if vendor_clean not in descs and vendor_clean not in configs_str:
                    continue

        entry = _parse_cve_entry(item)
        if entry.get("id"):
            seen[entry["id"]] = entry

    if not seen:
        return {"status": "unmatched", "cves": [], "reason": "no_matching_cves"}

    cves = sorted(
        seen.values(),
        key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)),
    )
    res = {"status": "matched", "cves": cves, "source": "nvd"}
    if is_version_wildcard:
        res["version_unspecified"] = True
    return res


def _parse_circl_entry(item: Any) -> Optional[Dict[str, Any]]:
    if isinstance(item, str):
        return {"id": item, "severity": "UNKNOWN", "cvss": None}

    if not isinstance(item, dict):
        return None

    cve_id = item.get("id") or item.get("cveId") or item.get("cveMetadata", {}).get("cveId")
    if not cve_id:
        return None

    severity, score = "UNKNOWN", None
    if "cvss" in item:
        try:
            score = float(item["cvss"])
        except (TypeError, ValueError):
            score = None

    containers = item.get("containers", {})
    metric_sources = list(containers.get("cna", {}).get("metrics", []))
    for adp in containers.get("adp", []):
        metric_sources.extend(adp.get("metrics", []))

    for metric in metric_sources:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                data = metric[key]
                score = data.get("baseScore", score)
                severity = data.get("baseSeverity", severity)
                break

    return {"id": cve_id, "severity": severity, "cvss": score}


def lookup_by_vendor_product(vendor: Optional[str], product: Optional[str]) -> Dict[str, Any]:
    """Fallback CVE lookup against CIRCL's Vulnerability-Lookup service."""
    if not vendor or not product:
        return {"status": "unmatched", "cves": [], "reason": "no_vendor_product"}

    try:
        r = requests.get(f"{CIRCL_URL}/{vendor}/{product}", timeout=20)
        if r.status_code == 404:
            return {"status": "unmatched", "cves": [], "reason": "no_matching_cves"}
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException as e:
        return {"status": "error", "cves": [], "reason": f"request_failed: {e}"}
    except ValueError:
        return {"status": "error", "cves": [], "reason": "invalid_json_response"}

    items = data if isinstance(data, list) else data.get("results", data.get("data", []))

    seen = {}
    for item in items:
        entry = _parse_circl_entry(item)
        if entry and entry.get("id"):
            seen[entry["id"]] = entry

    if not seen:
        return {"status": "unmatched", "cves": [], "reason": "no_matching_cves"}

    cves = sorted(seen.values(), key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
    return {"status": "matched", "cves": cves, "source": "circl"}


# ---------------------------------------------------------------------------
# Main CVE Lookup Entry Point with 7-Day SQLite Cache & Enrichment
# ---------------------------------------------------------------------------

def lookup_cves(cpe22_raw: Any, bypass_cache: bool = False) -> Dict[str, Any]:
    """
    Combined entry point with 7-day SQLite caching, NVD lookup, CIRCL fallback,
    and enrichment with EPSS probabilities and CISA Known Exploited Vulnerabilities.
    """
    cpe_normalized = cpe22_raw[0] if isinstance(cpe22_raw, list) and cpe22_raw else cpe22_raw
    if not cpe_normalized or not isinstance(cpe_normalized, str):
        return {"status": "unmatched", "cves": [], "reason": "no_cpe_available"}

    # 1. Check SQLite Cache
    if not bypass_cache:
        cached_result = get_cached_cpe(cpe_normalized)
        if cached_result:
            # Self-healing check: purge corrupted cache entries containing bogus Ping of Death
            cves = cached_result.get("cves", [])
            has_bogus_ping = any(c.get("id") == "CVE-1999-0128" for c in cves)
            vendor, product = cpe22_vendor_product(cpe_normalized)
            if has_bogus_ping and product not in ("linux_kernel", "tcp_ip", "icmp"):
                # Evict corrupted cache entry
                with _db_lock:
                    with _open_db() as conn:
                        conn.cursor().execute("DELETE FROM cpe_cache WHERE cpe = ?", (cpe_normalized,))
            else:
                cached_result["cves"] = enrich_cves(cves)
                return cached_result

    # 2. Perform fresh lookups
    cpe23 = cpe22_to_cpe23(cpe_normalized)
    vendor, product = cpe22_vendor_product(cpe_normalized)
    alias_vendor = VENDOR_ALIASES.get((vendor, product)) if vendor and product else None

    vendor_candidates = [vendor]
    cpe23_candidates = [cpe23]
    if alias_vendor and alias_vendor != vendor:
        vendor_candidates.append(alias_vendor)
        if cpe23:
            cpe23_candidates.append(_with_vendor(cpe23, alias_vendor))

    nvd_results = []
    for candidate in cpe23_candidates:
        result = lookup_by_cpe(candidate)
        nvd_results.append(result)
        if result["status"] == "matched":
            result["cves"] = enrich_cves(result["cves"])
            set_cached_cpe(cpe_normalized, result)
            return result

    circl_results = []
    for candidate_vendor in vendor_candidates:
        result = lookup_by_vendor_product(candidate_vendor, product)
        circl_results.append(result)
        if result["status"] == "matched":
            tried_alias = candidate_vendor != vendor
            result["reason"] = (
                "nvd_unmatched_used_circl_fallback"
                + ("_with_vendor_alias" if tried_alias else "")
            )
            result["cves"] = enrich_cves(result["cves"])
            set_cached_cpe(cpe_normalized, result)
            return result

    all_results = nvd_results + circl_results
    combined_reason = "; ".join(
        [f"nvd={r.get('reason')}" for r in nvd_results]
        + [f"circl={r.get('reason')}" for r in circl_results]
    )
    status = "error" if any(r["status"] == "error" for r in all_results) else "unmatched"

    final_result = {"status": status, "cves": [], "reason": combined_reason}
    if status == "unmatched":
        set_cached_cpe(cpe_normalized, final_result)

    return final_result
