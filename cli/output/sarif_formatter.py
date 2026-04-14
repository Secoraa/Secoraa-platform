"""
SARIF v2.1.0 formatter for Secoraa API scanner findings.

Converts the dict returned by `run_api_scan()` into SARIF so it can be uploaded
to the GitHub Security tab via `github/codeql-action/upload-sarif`.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "Secoraa API Security Scanner"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://secoraa.io"

# SARIF severity levels: error | warning | note | none
_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "note",
    "INFO": "note",
}


def _level_for(severity: Optional[str]) -> str:
    return _SEVERITY_TO_LEVEL.get(str(severity or "").upper(), "none")


def _rule_id(owasp_category: Optional[str], title: Optional[str]) -> str:
    """Build a stable rule id from OWASP category + title."""
    if owasp_category:
        # e.g. "API1:2023 - BOLA" → "API1-2023-BOLA"
        return re.sub(r"[^A-Za-z0-9]+", "-", str(owasp_category)).strip("-")
    # Fallback: slugified title
    return re.sub(r"[^A-Za-z0-9]+", "-", str(title or "unknown")).strip("-").lower()


def _parse_endpoint(endpoint: Optional[str]) -> Dict[str, str]:
    """
    Pull method + url out of a scanner endpoint string like "GET https://x/foo".
    Returns {"method": "...", "url": "...", "path": "..."} with best-effort values.
    """
    if not endpoint:
        return {"method": "", "url": "", "path": ""}
    parts = str(endpoint).strip().split(None, 1)
    if len(parts) == 2 and parts[0].isupper():
        method, url = parts
    else:
        method, url = "", str(endpoint)
    try:
        parsed = urlparse(url)
        path = parsed.path or url
    except Exception:
        path = url
    return {"method": method, "url": url, "path": path}


def _build_rule(finding: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = _rule_id(finding.get("owasp_category"), finding.get("title"))
    short = str(finding.get("title") or rule_id)
    full = str(finding.get("description") or short)
    help_text = str(
        finding.get("remediation")
        or "Review the finding and apply appropriate mitigations."
    )
    properties: Dict[str, Any] = {
        "tags": ["security", "api", "owasp"],
        "precision": "medium",
    }
    if finding.get("cvss_score") is not None:
        try:
            properties["security-severity"] = f"{float(finding['cvss_score']):.1f}"
        except (TypeError, ValueError):
            pass
    if finding.get("owasp_category"):
        properties["owasp-category"] = str(finding["owasp_category"])
    return {
        "id": rule_id,
        "name": re.sub(r"[^A-Za-z0-9]+", "", short)[:120] or rule_id,
        "shortDescription": {"text": short[:500]},
        "fullDescription": {"text": full[:2000]},
        "help": {
            "text": help_text[:2000],
            "markdown": f"**Remediation**\n\n{help_text}",
        },
        "defaultConfiguration": {"level": _level_for(finding.get("severity"))},
        "properties": properties,
    }


def _build_result(finding: Dict[str, Any], rule_index: int) -> Dict[str, Any]:
    ep = _parse_endpoint(finding.get("endpoint"))
    message = str(
        finding.get("description")
        or finding.get("title")
        or "Security finding"
    )
    result: Dict[str, Any] = {
        "ruleId": _rule_id(finding.get("owasp_category"), finding.get("title")),
        "ruleIndex": rule_index,
        "level": _level_for(finding.get("severity")),
        "message": {"text": message[:2000]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ep["url"] or ep["path"] or "unknown",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
        ],
        "properties": {},
    }
    if ep["method"]:
        result["properties"]["http-method"] = ep["method"]
    if finding.get("cvss_score") is not None:
        try:
            result["properties"]["security-severity"] = f"{float(finding['cvss_score']):.1f}"
        except (TypeError, ValueError):
            pass
    if finding.get("cvss_vector"):
        result["properties"]["cvss-vector"] = str(finding["cvss_vector"])
    if finding.get("confidence"):
        result["properties"]["confidence"] = str(finding["confidence"])
    if finding.get("impact"):
        result["properties"]["impact"] = str(finding["impact"])[:1000]
    return result


def generate_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a scanner report dict into a SARIF v2.1.0 document.

    `report` is the dict returned by `run_api_scan()` — it must contain a
    "findings" list whose entries follow the `make_finding(...)` shape used by
    the API scanner test modules.
    """
    findings: List[Dict[str, Any]] = list(report.get("findings") or [])

    # Deduplicate rules by id while preserving first-seen order.
    rules: List[Dict[str, Any]] = []
    rule_index_by_id: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rid = _rule_id(finding.get("owasp_category"), finding.get("title"))
        if rid not in rule_index_by_id:
            rule_index_by_id[rid] = len(rules)
            rules.append(_build_rule(finding))
        results.append(_build_result(finding, rule_index_by_id[rid]))

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": TOOL_URI,
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "scanName": report.get("scan_name"),
            "baseUrl": report.get("base_url"),
            "totalEndpoints": report.get("total_endpoints"),
            "totalFindings": report.get("total_findings", len(findings)),
            "scanMode": report.get("scan_mode"),
        },
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
