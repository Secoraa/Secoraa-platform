"""
OSV-backed CVE lookup for network scanner findings.

The network scanner's banner_grab / ssh_audit / http_service plugins now
attach a `software={"name": ..., "version": ...}` hint to any finding
where they extracted a versioned product. The orchestrator passes those
hints here, we query OSV (https://osv.dev), and emit one synthetic
Finding per matched CVE — with proper CVSS scores instead of heuristic
severity defaults.

Why OSV:
- Free, public, no API key required
- Aggregates Debian, Ubuntu, Alpine, RedHat, npm, pypi, etc.
- Returns structured CVSS vectors when available

Coverage gotchas:
- OSV is strongest for language ecosystems (npm, pypi). Coverage of
  system packages (OpenSSH, nginx, Apache) goes through Debian/Ubuntu/
  Alpine security trackers — solid for recent versions, spotty for
  ancient ones (e.g. nginx 1.14.0).
- Package names vary across ecosystems: 'openssh' vs 'openssh-server'.
  We try a small fan-out of name + ecosystem combinations and dedupe by
  CVE id.

Defensive design:
- 8s timeout per query, never blocks the scan permanently.
- In-process cache — same scan often produces multiple version-disclosure
  findings for the same product (banner_grab + ssh_audit both report
  OpenSSH on port 22), so we de-dupe lookups.
- Failures are silent: returning [] just means "no CVEs surfaced", not
  "scan failed".
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
HTTP_TIMEOUT = 8.0
# Limit how many CVEs we surface per (product, version) pair. Raw OSV can
# return 50+ for old OpenSSH; the report becomes noise. Keep the worst-N.
MAX_CVES_PER_PRODUCT = 5

# Ecosystem fan-out. Order matters: more-specific first (we dedupe by id
# so first-hit wins for any given CVE).
_ECOSYSTEM_FALLBACKS = [
    None,        # Try without ecosystem first (some packages match generically)
    "Debian",
    "Ubuntu",
    "Alpine",
    "Wolfi",
]

# Map detected banner names to the package names OSV is most likely to
# index them under. Keys are case-insensitive substrings.
_PACKAGE_NAME_MAP = {
    "openssh": "openssh",
    "ssh-": "openssh",
    "nginx": "nginx",
    "apache": "apache",
    "apache2": "apache",
    "lighttpd": "lighttpd",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis",
    "memcached": "memcached",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "exim": "exim",
    "postfix": "postfix",
    "samba": "samba",
}

_CACHE: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}


def _normalize_software(name: str, version: str) -> Optional[Tuple[str, str]]:
    """Map a free-text product name + version into a normalized OSV query key."""
    if not name or not version:
        return None
    name_lc = str(name).lower().strip()
    version = str(version).strip()

    # Pull ONLY the version core (drop trailing distro suffix, build metadata)
    # e.g. "OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" → "6.6.1p1"
    version_match = re.match(r"^([0-9][0-9a-z\.\-]*)", version)
    if version_match:
        version = version_match.group(1).rstrip(".-")

    # Look up a canonical package name. Substring match handles things like
    # "Apache/2.4.7" → "apache" or "OpenSSH_6.6.1p1" → "openssh".
    canonical: Optional[str] = None
    for key, pkg in _PACKAGE_NAME_MAP.items():
        if key in name_lc:
            canonical = pkg
            break
    if not canonical:
        # Last-ditch: take the first alphanumeric token before slash/space/underscore.
        token = re.split(r"[/\s_]", name_lc, maxsplit=1)[0]
        if token:
            canonical = token
        else:
            return None
    return (canonical, version)


def _query_osv(name: str, version: str, ecosystem: Optional[str]) -> List[Dict[str, Any]]:
    """Single OSV query. Returns list of vuln records or [] on any failure."""
    pkg: Dict[str, str] = {"name": name}
    if ecosystem:
        pkg["ecosystem"] = ecosystem
    payload = {"version": version, "package": pkg}
    try:
        resp = requests.post(OSV_ENDPOINT, json=payload, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json() or {}
        vulns = data.get("vulns") or []
        return vulns if isinstance(vulns, list) else []
    except Exception as exc:
        logger.debug("OSV query failed for %s@%s (%s): %s", name, version, ecosystem, exc)
        return []


def _extract_cvss(record: Dict[str, Any]) -> Tuple[float, Optional[str], str]:
    """
    Pull CVSS vector + score from an OSV record. OSV stores a list of
    severity entries with type=CVSS_V3 and score=<vector string>. We feed
    the vector through python's `cvss` lib if available; otherwise we
    return 0.0 and let the heuristic mapper kick in.
    """
    try:
        from cvss import CVSS3, CVSS2  # type: ignore
    except ImportError:
        CVSS3 = CVSS2 = None  # type: ignore

    for sev in record.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        sev_type = (sev.get("type") or "").upper()
        vector = sev.get("score")  # OSV stores the vector string in the "score" field
        if not vector:
            continue
        if sev_type == "CVSS_V3" and CVSS3 is not None:
            try:
                score = float(CVSS3(vector).base_score)
            except Exception:
                continue
        elif sev_type == "CVSS_V2" and CVSS2 is not None:
            try:
                score = float(CVSS2(vector).base_score)
            except Exception:
                continue
        else:
            continue

        if score >= 9.0:
            label = "CRITICAL"
        elif score >= 7.0:
            label = "HIGH"
        elif score >= 4.0:
            label = "MEDIUM"
        elif score > 0.0:
            label = "LOW"
        else:
            label = "INFORMATIONAL"
        return score, vector, label
    return 0.0, None, "INFORMATIONAL"


def _summarize(record: Dict[str, Any]) -> str:
    """Short human-readable summary for the finding description."""
    summary = record.get("summary") or ""
    if not summary:
        details = record.get("details") or ""
        summary = details.split("\n", 1)[0] if details else ""
    return (summary or "")[:300].strip()


def _references(record: Dict[str, Any]) -> Optional[str]:
    refs = record.get("references") or []
    urls = [r.get("url") for r in refs if isinstance(r, dict) and r.get("url")]
    if not urls:
        return None
    # Prefer NVD links when present, then advisory, then anything.
    nvd = [u for u in urls if "nvd.nist.gov" in u]
    if nvd:
        return nvd[0]
    return urls[0]


def lookup_cves(name: str, version: str) -> List[Dict[str, Any]]:
    """
    Look up CVEs for a product+version pair.

    Returns a list of dicts (at most MAX_CVES_PER_PRODUCT, sorted by
    severity descending) with keys: id, summary, cvss_score, cvss_vector,
    severity, reference.
    """
    norm = _normalize_software(name, version)
    if not norm:
        return []
    if norm in _CACHE:
        return _CACHE[norm]

    canonical_name, normalized_version = norm
    seen: Dict[str, Dict[str, Any]] = {}

    for ecosystem in _ECOSYSTEM_FALLBACKS:
        for pkg_variant in _name_variants(canonical_name):
            for record in _query_osv(pkg_variant, normalized_version, ecosystem):
                cve_id = record.get("id")
                if not cve_id or cve_id in seen:
                    continue
                cvss_score, cvss_vector, severity_label = _extract_cvss(record)
                seen[cve_id] = {
                    "id": cve_id,
                    "summary": _summarize(record),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "severity": severity_label,
                    "reference": _references(record),
                }
        if len(seen) >= MAX_CVES_PER_PRODUCT * 3:
            # We have plenty of candidates; stop fanning out and let the
            # severity sort pick the worst N.
            break

    sorted_cves = sorted(
        seen.values(),
        key=lambda c: (-(c.get("cvss_score") or 0.0), c.get("id") or ""),
    )[:MAX_CVES_PER_PRODUCT]
    _CACHE[norm] = sorted_cves
    return sorted_cves


def _name_variants(name: str) -> List[str]:
    """A few common name spellings OSV might index a package under."""
    variants = [name]
    # Many OS distributions split server packages: openssh-server, nginx-core,
    # apache2 vs apache. Add the most common forms.
    if name == "openssh":
        variants += ["openssh-server"]
    elif name == "apache":
        variants += ["apache2", "httpd"]
    elif name == "mysql":
        variants += ["mysql-server", "mariadb"]
    elif name == "postgresql":
        variants += ["postgres"]
    return variants
