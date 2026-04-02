from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from cvss import CVSS3  # type: ignore
except ImportError:
    CVSS3 = None
    logger.warning("cvss library not installed — CVSS scoring disabled")


def calculate_cvss(vector_string: str) -> float:
    """Compute CVSS 3.1 base score from a vector string."""
    if CVSS3 is None:
        return 0.0
    try:
        c = CVSS3(vector_string)
        return round(float(c.base_score), 1)
    except Exception as exc:
        logger.warning("Failed to compute CVSS for %s: %s", vector_string, exc)
        return 0.0


def severity_from_score(score: float) -> str:
    """Map a CVSS score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"
