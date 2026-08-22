import os
import time
import threading

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Free, no-key-required fallback source (aggregates NVD plus GitHub Advisory
# DB, CSAF feeds, etc.) - used when NVD errors out or has nothing for a CPE
# NVD couldn't match exactly (e.g. wildcarded/version-less CPEs).
CIRCL_URL = "https://vulnerability.circl.lu/api/search"

# nmap's service-probes fingerprint DB embeds vendor names that were correct
# when the CPE was assigned, but NVD's CPE Dictionary keeps a canonical name
# and renames/deprecates entries when e.g. a company gets acquired. nmap
# doesn't track those renames, so its CPE can permanently point at a vendor
# string NVD no longer recognizes - not a version problem, a naming one.
# This is a starting list of known cases, not an exhaustive one; add to it
# as you hit more (check https://nvd.nist.gov/products/cpe/search for the
# "This CPE has been deprecated to" chain on any suspiciously-empty result).
VENDOR_ALIASES = {
    ("igor_sysoev", "nginx"): "f5",  # igor_sysoev:nginx -> nginx:nginx -> f5:nginx
}

# Optional: export NVD_API_KEY to raise the rate limit from 5 req/30s to
# 50 req/30s. Get one free at https://nvd.nist.gov/developers/request-an-api-key
API_KEY = os.environ.get("NVD_API_KEY")

# Minimum seconds between requests, kept safely under NVD's documented limits.
_MIN_INTERVAL = 0.7 if API_KEY else 6.5

_throttle_lock = threading.Lock()
_last_request_time = 0.0


def _throttle():
    """Block just long enough to stay under NVD's rate limit."""
    global _last_request_time
    with _throttle_lock:
        wait = _MIN_INTERVAL - (time.time() - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.time()


def _headers():
    return {"apiKey": API_KEY} if API_KEY else {}


def cpe22_to_cpe23(cpe22):
    """
    Converts nmap's CPE 2.2 URI format (cpe:/a:vendor:product:version[:update])
    into a CPE 2.3 formatted string (cpe:2.3:a:vendor:product:version:update:*:*:*:*:*:*).

    Returns None (not a best-effort guess) if the input isn't a clean,
    unambiguous CPE 2.2 string - callers should treat that as "no reliable
    CPE available" rather than silently falling back to a weaker match.
    """
    if isinstance(cpe22, list):
        cpe22 = cpe22[0] if cpe22 else ""

    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None

    body = cpe22[len("cpe:/"):]
    parts = body.split(":")

    # More than 5 segments means nmap packed extra fields (edition, target,
    # etc.) into the string. Rather than truncate and silently discard that
    # data - which can produce a CPE that matches the wrong thing - bail out.
    if len(parts) > 5:
        return None

    if not parts or parts[0] not in ("a", "o", "h"):
        return None

    while len(parts) < 5:
        parts.append("*")

    return "cpe:2.3:" + ":".join(parts) + ":*:*:*:*:*:*"


def cpe22_vendor_product(cpe22):
    """
    Extracts (vendor, product) from an nmap CPE 2.2 string, e.g.
    'cpe:/a:igor_sysoev:nginx' -> ('igor_sysoev', 'nginx').
    Returns (None, None) if it can't be parsed - callers should treat that
    as "no vendor/product available" rather than guessing.
    """
    if isinstance(cpe22, list):
        cpe22 = cpe22[0] if cpe22 else ""

    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None, None

    parts = cpe22[len("cpe:/"):].split(":")
    if len(parts) < 3:
        return None, None

    return (parts[1] or None), (parts[2] or None)


def _with_vendor(cpe23, vendor):
    """Returns cpe23 with its vendor field (position 3) replaced."""
    fields = cpe23.split(":")
    if len(fields) <= 3:
        return cpe23
    fields[3] = vendor
    return ":".join(fields)

def _parse_cve_entry(item):
    cve = item["cve"]
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
    return {"id": cve["id"], "severity": severity, "cvss": score}


def lookup_by_cpe(cpe23):
    """
    Looks up CVEs for an exact CPE 2.3 string via NVD's cpeName match
    (version-specific, not free-text keyword search).

    Returns:
        {
            "status": "matched" | "unmatched" | "error",
            "cves": [{"id": ..., "severity": ..., "cvss": ...}, ...],
            "reason": <present only for "unmatched"/"error">
        }

    "matched" with an empty cves list should not occur (that's "unmatched"),
    but the two are kept distinct on purpose: "unmatched" means NVD was
    reached and confirmed no hits; "error" means we don't actually know.
    Never conflate the two - a security tool that reports "error" as "clean"
    is worse than one that crashes.
    """
    if not cpe23:
        return {"status": "unmatched", "cves": [], "reason": "no_cpe_available"}

    # `cpeName` is an exact-match lookup - it only works if cpe23 exists as a
    # literal entry in NVD's CPE Dictionary. Any wildcard segment (almost
    # always the version, since nmap frequently can't determine it) means
    # that will never be true, and NVD returns a 404 instead of "no CVEs".
    # `virtualMatchString` is built for exactly this case: it matches
    # broadly against CVEs' applicability statements instead of requiring a
    # literal dictionary hit.
    param_name = "virtualMatchString" if "*" in cpe23 else "cpeName"

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

    # Dedup by CVE ID (NVD can return the same CVE via multiple config matches).
    seen = {}
    for item in data.get("vulnerabilities", []):
        entry = _parse_cve_entry(item)
        seen[entry["id"]] = entry

    if not seen:
        return {"status": "unmatched", "cves": [], "reason": "no_matching_cves"}

    cves = sorted(
        seen.values(),
        key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)),
    )

    return {"status": "matched", "cves": cves, "source": "nvd"}


def _parse_circl_entry(item):
    """
    Best-effort parse of a CIRCL Vulnerability-Lookup record. CIRCL's
    search endpoint isn't consistent about what it hands back - sometimes
    a bare CVE-ID string, sometimes a legacy cve-search dict, sometimes a
    full CVE Record v5 JSON object - so this checks each shape in turn
    and falls back to "UNKNOWN" severity rather than dropping the entry
    entirely: an unscored CVE ID is still more useful to a reader than
    silently discarding it.
    """
    if isinstance(item, str):
        return {"id": item, "severity": "UNKNOWN", "cvss": None}

    if not isinstance(item, dict):
        return None

    cve_id = (
        item.get("id")
        or item.get("cveId")
        or item.get("cveMetadata", {}).get("cveId")
    )
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


def lookup_by_vendor_product(vendor, product):
    """
    Fallback CVE lookup against CIRCL's Vulnerability-Lookup service
    (https://vulnerability.circl.lu), searched by vendor/product name
    rather than requiring an exact CPE match. This is the right tool when
    nmap couldn't determine a version (so no reliable CPE exists at all)
    or when NVD itself is erroring - CIRCL aggregates NVD plus several
    other advisory feeds (GitHub Advisory DB, CSAF sources, etc.), so it
    isn't just a mirror of the same single point of failure.
    """
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
        if entry:
            seen[entry["id"]] = entry

    if not seen:
        return {"status": "unmatched", "cves": [], "reason": "no_matching_cves"}

    cves = sorted(seen.values(), key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
    return {"status": "matched", "cves": cves, "source": "circl"}


def lookup_cves(cpe22_raw):
    """
    Combined entry point: try NVD first via its exact CPE (best data
    quality, official CVSS scoring), then fall back to CIRCL's
    vendor/product search if NVD didn't match anything or errored out.
    This means a single source's outage, or an nmap CPE with no detected
    version, no longer leaves a scanned service with zero CVE coverage.

    Also tries a known vendor alias (see VENDOR_ALIASES) against both
    sources - nmap's CPEs can carry a vendor name NVD has since renamed
    (e.g. after an acquisition), which looks identical to "no CVEs exist"
    unless you specifically account for it.
    """
    cpe23 = cpe22_to_cpe23(cpe22_raw)
    vendor, product = cpe22_vendor_product(cpe22_raw)
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
            return result

    circl_results = []
    for candidate_vendor in vendor_candidates:
        result = lookup_by_vendor_product(candidate_vendor, product)
        circl_results.append(result)
        if result["status"] == "matched":
            tried_alias = candidate_vendor != vendor
            result["reason"] = (
                f"nvd_unmatched_used_circl_fallback"
                + ("_with_vendor_alias" if tried_alias else "")
            )
            return result

    # Nothing matched anywhere, even after trying a known vendor alias. If
    # any attempt actually failed (rather than cleanly confirming "no
    # CVEs"), report "error" - a security tool that reports "error" as
    # "clean" is worse than one that's upfront about not actually knowing.
    all_results = nvd_results + circl_results
    combined_reason = "; ".join(
        [f"nvd={r.get('reason')}" for r in nvd_results]
        + [f"circl={r.get('reason')}" for r in circl_results]
    )
    status = "error" if any(r["status"] == "error" for r in all_results) else "unmatched"

    return {"status": status, "cves": [], "reason": combined_reason}