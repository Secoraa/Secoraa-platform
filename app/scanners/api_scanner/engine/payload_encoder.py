from __future__ import annotations

import urllib.parse
from typing import List, Tuple


def encode_payload(payload: str, context: str = "query") -> List[Tuple[str, str]]:
    """
    Generate encoded variants of a payload for WAF bypass.

    Args:
        payload: Raw payload string
        context: Where the payload is injected — "query", "body", "header", "path"

    Returns:
        List of (encoded_payload, encoding_description) tuples.
        Always includes the original payload as the first entry.
    """
    variants: List[Tuple[str, str]] = []

    # Always include the raw payload first
    variants.append((payload, "raw"))

    # URL encoding (single)
    url_encoded = urllib.parse.quote(payload, safe="")
    if url_encoded != payload:
        variants.append((url_encoded, "url-encoded"))

    # Double URL encoding (for proxied backends that decode twice)
    double_encoded = urllib.parse.quote(url_encoded, safe="")
    if double_encoded != url_encoded:
        variants.append((double_encoded, "double-url-encoded"))

    # Unicode escape sequences for key SQL/injection characters
    unicode_variant = _unicode_encode(payload)
    if unicode_variant != payload:
        variants.append((unicode_variant, "unicode-escaped"))

    # HTML entity encoding
    html_variant = _html_entity_encode(payload)
    if html_variant != payload:
        variants.append((html_variant, "html-entity"))

    # Case variation for SQL keywords
    if context in ("query", "body"):
        case_variant = _case_toggle_sql(payload)
        if case_variant != payload:
            variants.append((case_variant, "case-toggled"))

    # Comment insertion in SQL keywords
    if context in ("query", "body"):
        comment_variant = _sql_comment_insert(payload)
        if comment_variant != payload:
            variants.append((comment_variant, "sql-comment-inserted"))

    # Whitespace alternatives (tabs, newlines, comments as space)
    space_variant = _space_alternatives(payload)
    if space_variant != payload:
        variants.append((space_variant, "alt-whitespace"))

    return variants


def _unicode_encode(payload: str) -> str:
    """Replace key injection characters with Unicode escape sequences."""
    replacements = {
        "'": "\\u0027",
        '"': "\\u0022",
        "<": "\\u003c",
        ">": "\\u003e",
        ";": "\\u003b",
        "|": "\\u007c",
        "&": "\\u0026",
    }
    result = payload
    for char, escape in replacements.items():
        result = result.replace(char, escape)
    return result


def _html_entity_encode(payload: str) -> str:
    """Replace key characters with HTML entity equivalents."""
    replacements = {
        "'": "&#39;",
        '"': "&#34;",
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
    }
    result = payload
    for char, entity in replacements.items():
        result = result.replace(char, entity)
    return result


# SQL keywords to target for case toggling and comment insertion
_SQL_KEYWORDS = [
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
    "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING",
    "SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "NULL",
    "CONCAT", "CAST", "CONVERT", "LOAD_FILE", "INTO",
    "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME",
]


def _case_toggle_sql(payload: str) -> str:
    """Toggle case of SQL keywords: SELECT -> sElEcT."""
    result = payload
    for kw in _SQL_KEYWORDS:
        # Case-insensitive find and replace with toggled version
        toggled = "".join(
            c.upper() if i % 2 == 1 else c.lower()
            for i, c in enumerate(kw)
        )
        # Replace whole-word occurrences (case-insensitive)
        import re
        result = re.sub(
            r'\b' + re.escape(kw) + r'\b',
            toggled,
            result,
            flags=re.IGNORECASE,
        )
    return result


def _sql_comment_insert(payload: str) -> str:
    """Insert inline comments into SQL keywords: UNION SELECT -> UN/**/ION SEL/**/ECT."""
    result = payload
    for kw in _SQL_KEYWORDS:
        if len(kw) < 4:
            continue  # Skip short keywords (OR, AND) — comments look weird
        mid = len(kw) // 2
        commented = kw[:mid] + "/**/" + kw[mid:]
        import re
        result = re.sub(
            r'\b' + re.escape(kw) + r'\b',
            commented,
            result,
            flags=re.IGNORECASE,
        )
    return result


def _space_alternatives(payload: str) -> str:
    """Replace spaces with alternative whitespace that may bypass WAF rules."""
    # Use tab character as space alternative
    return payload.replace(" ", "\t")


def encode_for_context(payload: str, context: str = "query", max_variants: int = 4) -> List[Tuple[str, str]]:
    """
    Like encode_payload but limits the number of variants returned.
    Prioritizes the most effective encodings for the given context.

    For high-volume testing, use this to avoid sending too many requests.
    """
    all_variants = encode_payload(payload, context)

    # Priority order depends on context
    if context == "query":
        priority = ["raw", "url-encoded", "double-url-encoded", "case-toggled", "sql-comment-inserted"]
    elif context == "body":
        priority = ["raw", "unicode-escaped", "case-toggled", "sql-comment-inserted", "html-entity"]
    elif context == "header":
        priority = ["raw", "url-encoded", "unicode-escaped"]
    else:
        priority = ["raw", "url-encoded", "unicode-escaped", "case-toggled"]

    # Sort by priority, keeping only max_variants
    ordered = []
    for pname in priority:
        for v in all_variants:
            if v[1] == pname and v not in ordered:
                ordered.append(v)
    # Add any remaining variants not in priority list
    for v in all_variants:
        if v not in ordered:
            ordered.append(v)

    return ordered[:max_variants]
