"""
Gate check logic for CI runs.

Decides whether a scan should pass or fail based on severity threshold and
optional ignored OWASP rule categories.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

_SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "INFO": 1,
}


@dataclass
class GateResult:
    passed: bool
    threshold: str
    findings_above: int
    total_findings: int
    severity_counts: Dict[str, int] = field(default_factory=dict)
    ignored_count: int = 0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "threshold": self.threshold,
            "above_threshold": self.findings_above,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "ignored_count": self.ignored_count,
            "summary": self.summary,
        }


def _weight(sev: Optional[str]) -> int:
    return _SEVERITY_WEIGHT.get(str(sev or "").upper(), 0)


def check_gate(
    findings: List[Dict[str, Any]],
    threshold: str = "HIGH",
    ignore_rules: Optional[Iterable[str]] = None,
) -> GateResult:
    """
    Count findings at or above the threshold severity, excluding anything
    whose `owasp_category` matches an entry in `ignore_rules`.
    """
    threshold = (threshold or "HIGH").upper()
    tw = _weight(threshold)
    ignored = {str(r).strip().lower() for r in (ignore_rules or []) if r}

    counts: Dict[str, int] = {}
    above = 0
    ignored_count = 0
    kept = 0

    for f in findings or []:
        category = str(f.get("owasp_category") or "").strip().lower()
        if ignored and category and any(tag in category for tag in ignored):
            ignored_count += 1
            continue
        kept += 1
        sev = str(f.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
        if _weight(sev) >= tw:
            above += 1

    passed = above == 0
    summary = (
        f"{'PASSED' if passed else 'FAILED'}: {above} finding(s) at or above {threshold}"
        f" (total: {kept}"
        + (f", ignored: {ignored_count}" if ignored_count else "")
        + ")"
    )

    return GateResult(
        passed=passed,
        threshold=threshold,
        findings_above=above,
        total_findings=kept,
        severity_counts=counts,
        ignored_count=ignored_count,
        summary=summary,
    )
