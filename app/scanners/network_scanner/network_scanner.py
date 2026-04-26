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
