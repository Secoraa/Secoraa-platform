"""
NetworkScanner — orchestrates plugin-based vulnerability scanning of an IP.

The scanner runs the extended_ports plugin first (it discovers open ports
and populates the shared list), then runs every other registered plugin
which consumes that list. Plugins can opt out of a target by no-op'ing
when the relevant port is closed.

Findings are returned as serializable dicts keyed for the worker pipeline
in `app/api/scans.py`, which converts them into Vulnerability rows.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.scanners.base import BaseScanner
from app.scanners.network_scanner.plugins import ALL_PLUGINS, Finding

logger = logging.getLogger(__name__)


_SEVERITY_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.1,
    "INFORMATIONAL": 0.0,
}


def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to a Vulnerability-shaped dict for downstream insertion."""
    data = asdict(finding)
    if not data.get("cvss_score"):
        data["cvss_score"] = _SEVERITY_TO_CVSS.get(finding.severity.upper(), 0.0)
    return data


def _enrich_with_cves(findings: List[Finding]) -> List[Finding]:
    """
    For every unique (software_name, software_version) referenced by an
    existing finding, look up CVEs against OSV and emit one synthetic
    Finding per CVE. Each enrichment finding inherits the port from the
    first finding that mentioned that software, so the platform UI shows
    the CVE alongside the offending service.

    Imported lazily so a missing OSV reachable host or the cve library
    never blocks the rest of the scan.
    """
    seen_keys: Dict[tuple, int] = {}  # (name, version) -> port (first seen)
    for f in findings:
        sw = getattr(f, "software", None)
        if not sw:
            continue
        key = (str(sw.get("name") or "").lower(), str(sw.get("version") or "").strip())
        if not key[0] or not key[1]:
            continue
        if key not in seen_keys:
            seen_keys[key] = f.port

    if not seen_keys:
        return []

    try:
        from app.scanners.network_scanner.cve_lookup import lookup_cves
    except Exception as exc:
        logger.warning("CVE enrichment skipped — cve_lookup import failed: %s", exc)
        return []

    out: List[Finding] = []
    for (name, version), port in seen_keys.items():
        try:
            cves = lookup_cves(name, version)
        except Exception as exc:
            logger.debug("CVE lookup failed for %s@%s: %s", name, version, exc)
            continue
        for cve in cves:
            severity = str(cve.get("severity") or "INFORMATIONAL").upper()
            cve_id = cve.get("id") or "CVE-UNKNOWN"
            tags = ["cve", f"cve:{cve_id}", f"product:{name}"]
            if port is not None:
                tags.append(f"port:{port}")
            out.append(
                Finding(
                    plugin="cve_lookup",
                    title=f"{cve_id} — {name} {version}",
                    severity=severity,
                    description=(
                        f"OSV-matched CVE for {name} {version}. "
                        + (cve.get("summary") or "No summary provided.")
                    ),
                    recommendation=(
                        f"Upgrade {name} to a patched version. See {cve.get('reference') or 'NVD'} "
                        f"for fix details."
                    ),
                    port=port,
                    service=name,
                    cvss_score=cve.get("cvss_score") or 0.0,
                    cvss_vector=cve.get("cvss_vector"),
                    reference=cve.get("reference"),
                    tags=tags,
                )
            )
    return out


def run_network_scan(target_ip: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Run every registered plugin against ``target_ip`` and return aggregate output."""
    open_ports: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    plugin_runs: List[Dict[str, Any]] = []
    # Guardrail: prevent any plugin from blocking the entire scan indefinitely.
    plugin_timeout = max(5.0, float(timeout) * 6.0)

    for plugin in ALL_PLUGINS:
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            future = pool.submit(plugin.runner, target_ip, open_ports, timeout)
            plugin_findings = future.result(timeout=plugin_timeout)
            findings.extend(plugin_findings)
            plugin_runs.append({"name": plugin.name, "count": len(plugin_findings)})
            logger.info(
                "network_scan plugin=%s findings=%d",
                plugin.name,
                len(plugin_findings),
            )
            pool.shutdown(wait=True)
        except FutureTimeoutError:
            logger.error(
                "network_scan plugin %s timed out after %.1fs",
                plugin.name,
                plugin_timeout,
            )
            try:
                future.cancel()
            except Exception:
                pass
            plugin_runs.append(
                {
                    "name": plugin.name,
                    "error": f"timeout after {plugin_timeout:.1f}s",
                }
            )
            # Do not block waiting on a timed-out plugin thread.
            pool.shutdown(wait=False, cancel_futures=True)
        except Exception as exc:
            logger.exception("network_scan plugin %s crashed: %s", plugin.name, exc)
            plugin_runs.append({"name": plugin.name, "error": str(exc)})
            pool.shutdown(wait=True)

    # ── CVE enrichment ────────────────────────────────────────────────
    # Plugins that detect a versioned product (banner_grab, ssh_audit,
    # http_service) attach a `software={"name", "version"}` hint to their
    # findings. Take each unique (name, version) tuple, query OSV, and
    # emit one synthetic finding per matched CVE so they show up in the
    # platform alongside heuristic findings.
    cve_findings = _enrich_with_cves(findings)
    findings.extend(cve_findings)
    if cve_findings:
        plugin_runs.append({"name": "cve_lookup", "count": len(cve_findings)})
        logger.info("network_scan plugin=cve_lookup findings=%d", len(cve_findings))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        severity_counts[f.severity.upper()] = severity_counts.get(f.severity.upper(), 0) + 1

    return {
        "scan_type": "network",
        "target": target_ip,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "open_ports": open_ports,
        "findings": [_finding_to_dict(f) for f in findings],
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "plugin_runs": plugin_runs,
    }


class NetworkScanner(BaseScanner):
    name = "network"

    def run(self, payload: dict) -> dict:
        target_ip = (payload.get("target_ip") or payload.get("ip") or "").strip()
        if not target_ip:
            raise ValueError("target_ip is required")
        timeout = float(payload.get("timeout", 1.0))
        return run_network_scan(target_ip, timeout=timeout)
