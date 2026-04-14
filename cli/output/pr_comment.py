"""
Generate a GitHub PR comment with scan results summary.

Uses the GITHUB_TOKEN to post a comment via the GitHub API.
Designed to run inside GitHub Actions where GITHUB_TOKEN and
GITHUB_REPOSITORY are available as environment variables.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import sys
from typing import Any, Dict, List, Optional


def _severity_emoji(sev: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFORMATIONAL": "🔵",
    }.get(sev.upper(), "⚪")


def build_comment_body(
    report: Dict[str, Any],
    gate: Dict[str, Any],
) -> str:
    """Build a markdown comment body from scan report and gate result."""
    findings: List[Dict[str, Any]] = report.get("findings") or []
    total = len(findings)
    base_url = report.get("base_url") or report.get("domain") or "n/a"
    duration = report.get("duration_seconds")
    endpoints = report.get("total_endpoints", 0)

    passed = gate.get("passed", True)
    threshold = gate.get("threshold", "HIGH")
    gate_icon = "✅" if passed else "❌"
    gate_label = "PASSED" if passed else "FAILED"

    # Severity counts
    counts = gate.get("severity_counts") or {}
    sev_lines = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        c = counts.get(sev, 0)
        if c > 0:
            sev_lines.append(f"| {_severity_emoji(sev)} {sev} | {c} |")

    sev_table = ""
    if sev_lines:
        sev_table = (
            "\n| Severity | Count |\n"
            "|----------|-------|\n"
            + "\n".join(sev_lines)
            + "\n"
        )

    # Top findings (max 10)
    findings_table = ""
    if findings:
        rows = []
        for f in findings[:10]:
            sev = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            endpoint = f.get("endpoint", "-")
            # Truncate long endpoints
            if len(endpoint) > 60:
                endpoint = endpoint[:57] + "..."
            rows.append(f"| {_severity_emoji(sev)} {sev} | {title} | `{endpoint}` |")

        findings_table = (
            "\n<details>\n<summary>Top findings (showing "
            f"{min(10, len(findings))} of {total})</summary>\n\n"
            "| Severity | Finding | Endpoint |\n"
            "|----------|---------|----------|\n"
            + "\n".join(rows)
            + "\n\n</details>\n"
        )

    duration_str = f" in {duration:.1f}s" if duration else ""

    body = f"""## {gate_icon} Secoraa API Security Scan — {gate_label}

**Target:** `{base_url}`
**Endpoints scanned:** {endpoints} | **Findings:** {total}{duration_str}
**Gate threshold:** {threshold}
{sev_table}{findings_table}
---
<sub>Powered by [Secoraa](https://secoraa.com) API Security Scanner</sub>
"""
    return body.strip()


def post_pr_comment(
    report: Dict[str, Any],
    gate: Dict[str, Any],
) -> bool:
    """Post a scan summary comment on the current PR.

    Requires GITHUB_TOKEN and runs inside a GitHub Actions PR context.
    Returns True if comment was posted successfully.
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")

    if not token or not repo:
        print(
            "[secoraa] Skipping PR comment: GITHUB_TOKEN or GITHUB_REPOSITORY not set",
            file=sys.stderr,
        )
        return False

    # Determine PR number
    pr_number = _get_pr_number()
    if not pr_number:
        print(
            "[secoraa] Skipping PR comment: not a pull_request event",
            file=sys.stderr,
        )
        return False

    body = build_comment_body(report, gate)

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            print(
                f"[secoraa] PR comment posted: {result.get('html_url', '')}",
                file=sys.stderr,
            )
            return True
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(
            f"[secoraa] Failed to post PR comment (HTTP {exc.code}): {err_body[:200]}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"[secoraa] Failed to post PR comment: {exc}", file=sys.stderr)

    return False


def _get_pr_number() -> Optional[int]:
    """Extract PR number from GitHub Actions environment."""
    # GITHUB_REF = refs/pull/123/merge
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/pull/"):
        parts = ref.split("/")
        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                pass

    # Fallback: GITHUB_EVENT_PATH contains the event payload
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            with open(event_path, "r") as f:
                event = json.load(f)
            pr = event.get("pull_request") or event.get("issue") or {}
            number = pr.get("number")
            if number:
                return int(number)
        except Exception:
            pass

    return None
