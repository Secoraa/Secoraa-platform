from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.engine.response_differ import compare_responses, responses_are_same
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API1:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

# Match any path parameter that looks like an ID
ID_PATTERN = re.compile(r"\{([a-z_]*id[a-z_]*)\}", re.IGNORECASE)

# Test IDs — sequential, zero, negative, large
TEST_IDS = ["1", "2", "100", "0", "-1", "999999"]


def _replace_ids(path: str, id_params: List[str], value: str) -> str:
    """Replace all ID placeholders in *path* with *value*."""
    for param_name in id_params:
        path = path.replace(f"{{{param_name}}}", value)
    return path


async def run_bola_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    secondary_auth_headers: Optional[Dict[str, str]] = None,
    secondary_query_params: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Run BOLA checks on endpoints with ID-like path parameters.

    Uses response diffing to reduce false positives and supports two-token
    testing (primary user vs. secondary user) for reliable BOLA detection.
    """
    findings: List[Dict[str, Any]] = []
    path: str = endpoint.get("path", "")
    method: str = endpoint.get("method", "GET")
    ep_label = f"{method} {path}"

    # ---- Step 1: Detect ID parameters ----------------------------------------
    id_params = ID_PATTERN.findall(path)
    if not id_params:
        return findings

    # ---- Step 2: Establish baseline (primary auth, ID=1) ---------------------
    baseline_path = _replace_ids(path, id_params, "1")
    baseline_url = build_url(base_url, baseline_path, query_params)

    baseline_resp, _ = await execute_request(
        method, baseline_url, headers={**auth_headers}
    )

    if baseline_resp is None:
        logger.debug("BOLA: baseline request failed for %s — skipping", ep_label)
        return findings

    # ---- Step 3: Unauthenticated BOLA test -----------------------------------
    unauth_bola_found = False

    if auth_headers:
        noauth_resp, noauth_evidence = await execute_request(
            method, baseline_url
        )

        if noauth_resp is not None:
            # Endpoint properly protected — skip unauthenticated tests
            if noauth_resp.status_code in (401, 403):
                logger.debug(
                    "BOLA: %s returned %d without auth — properly protected",
                    ep_label,
                    noauth_resp.status_code,
                )
            else:
                diff = compare_responses(baseline_resp, noauth_resp)

                if diff.verdict == "SAME" or (
                    diff.verdict == "SIMILAR" and diff.similarity_score > 0.8
                ):
                    unauth_bola_found = True
                    confidence = (
                        "HIGH" if diff.verdict == "SAME" else "MEDIUM"
                    )
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title="BOLA — Unauthenticated Access to Object (ID=1)",
                        cvss_vector=CVSS_VEC,
                        endpoint=ep_label,
                        description=(
                            "The endpoint returns the same data for object ID '1' "
                            "without any authentication. An unauthenticated request "
                            f"produced a '{diff.verdict}' response "
                            f"(similarity={diff.similarity_score:.2f}) compared to "
                            "the authenticated baseline."
                        ),
                        evidence=noauth_evidence,
                        impact=(
                            "Any unauthenticated attacker can enumerate object IDs "
                            "and access other users' data."
                        ),
                        remediation=(
                            "Implement server-side ownership validation. Verify the "
                            "authenticated user is authorized to access the requested "
                            "resource."
                        ),
                        confidence=confidence,
                        references=[REF],
                    ))

    # ---- Step 4: Two-token BOLA test -----------------------------------------
    if secondary_auth_headers is not None:
        secondary_qp = secondary_query_params if secondary_query_params else query_params
        secondary_url = build_url(base_url, baseline_path, secondary_qp)

        sec_resp, sec_evidence = await execute_request(
            method,
            secondary_url,
            headers={**secondary_auth_headers},
        )

        if sec_resp is not None:
            diff = compare_responses(baseline_resp, sec_resp)

            if diff.verdict == "SAME" or (
                diff.verdict == "SIMILAR" and diff.similarity_score > 0.8
            ):
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="BOLA — Cross-User Object Access (Two-Token)",
                    cvss_vector=CVSS_VEC,
                    endpoint=ep_label,
                    description=(
                        "A secondary user (User B) can access resources belonging "
                        "to the primary user (User A). The response for object "
                        f"ID '1' was '{diff.verdict}' "
                        f"(similarity={diff.similarity_score:.2f}) across both "
                        "user sessions."
                    ),
                    evidence=sec_evidence,
                    impact=(
                        "Authenticated users can access resources belonging to "
                        "other users by manipulating the object ID, leading to "
                        "unauthorized data exposure or modification."
                    ),
                    remediation=(
                        "Verify the authenticated user owns or has permission to "
                        "access the requested resource before returning data. "
                        "Use indirect object references or enforce ownership "
                        "checks at the data layer."
                    ),
                    confidence="HIGH",
                    references=[REF],
                ))

    # ---- Step 5: ID enumeration (remaining test IDs) -------------------------
    if not unauth_bola_found:
        for test_id in TEST_IDS:
            if test_id == "1":
                continue  # already tested as baseline

            enum_path = _replace_ids(path, id_params, test_id)
            enum_url = build_url(base_url, enum_path, query_params)

            enum_resp, enum_evidence = await execute_request(method, enum_url)

            if enum_resp is None:
                continue

            if enum_resp.status_code in (401, 403):
                continue

            if enum_resp.status_code == 200:
                diff = compare_responses(baseline_resp, enum_resp)

                # A successful response that is structurally similar to the
                # authenticated baseline (but not identical — different ID means
                # different data) is a strong IDOR signal.
                if diff.verdict in ("SAME", "SIMILAR") and diff.similarity_score > 0.6:
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"IDOR — Unauthenticated Object Enumeration (ID={test_id})",
                        cvss_vector=CVSS_VEC,
                        endpoint=ep_label,
                        description=(
                            f"The endpoint returns data for object ID '{test_id}' "
                            "without authentication. The response is structurally "
                            f"'{diff.verdict}' (similarity={diff.similarity_score:.2f}) "
                            "to the authenticated baseline, indicating the same type "
                            "of resource is exposed."
                        ),
                        evidence=enum_evidence,
                        impact=(
                            "Attackers can enumerate object IDs and access arbitrary "
                            "users' data without authentication."
                        ),
                        remediation=(
                            "Require authentication for all endpoints that return "
                            "user-specific data. Implement server-side authorization "
                            "checks to ensure the caller owns the requested resource."
                        ),
                        confidence="HIGH" if diff.verdict == "SAME" else "MEDIUM",
                        references=[REF],
                    ))
                    break  # one finding is enough to prove enumeration

    return findings
