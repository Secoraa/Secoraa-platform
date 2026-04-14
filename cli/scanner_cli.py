"""
Secoraa Scanner CLI — run the API and Subdomain scanners from a terminal.

Usage:
    python -m cli.scanner_cli api --target-url https://example.com --openapi-spec ./openapi.json
    python -m cli.scanner_cli subdomain --domain example.com

Exit codes:
    0 = scan passed (no findings above threshold)
    1 = scan failed the gate (findings >= threshold)
    2 = scan error (config, parse, or runtime failure)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is importable when invoked as `python -m cli.scanner_cli`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

logger = logging.getLogger("secoraa.cli")

# Severity ordering (higher = more severe)
_SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "INFO": 1,
}

EXIT_PASS = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
def _env_or(arg_value: Optional[str], env_key: str, default: Optional[str] = None) -> Optional[str]:
    """CLI arg takes precedence, fall back to env var, then default."""
    if arg_value:
        return arg_value
    env_val = os.environ.get(env_key)
    if env_val:
        return env_val
    return default


def _auto_detect_openapi_spec() -> Optional[str]:
    """Look for a spec file in the current working directory."""
    candidates = [
        "openapi.yaml",
        "openapi.yml",
        "openapi.json",
        "swagger.yaml",
        "swagger.yml",
        "swagger.json",
        "docs/openapi.yaml",
        "docs/openapi.json",
        "docs/swagger.json",
    ]
    for c in candidates:
        p = Path(c)
        if p.is_file():
            return str(p.resolve())
    return None


def _load_spec_file(path: str) -> Dict[str, Any]:
    """Load a JSON or YAML OpenAPI/Postman spec file into a dict."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Spec file not found: {path}")
    content = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to parse YAML specs. Install with: pip install pyyaml") from exc
        return yaml.safe_load(content) or {}
    # Default: JSON
    return json.loads(content)


def _build_auth_config(token: Optional[str], auth_type: str) -> Optional[Dict[str, Any]]:
    """Build an auth_config dict from CLI args/env vars."""
    if not token:
        return None
    auth_type = (auth_type or "bearer").lower()
    if auth_type == "bearer":
        return {"type": "bearer", "token": token}
    if auth_type == "api_key":
        header_name = os.environ.get("AUTH_HEADER_NAME", "X-API-Key")
        return {"type": "api_key", "header_name": header_name, "value": token}
    if auth_type == "basic":
        # token format: "user:pass"
        if ":" not in token:
            raise ValueError("For --auth-type basic, --auth-token must be in 'user:pass' format")
        user, _, pwd = token.partition(":")
        return {"type": "basic", "username": user, "password": pwd}
    raise ValueError(f"Unsupported auth-type: {auth_type}")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _severity_weight(sev: str) -> int:
    return _SEVERITY_WEIGHT.get(str(sev or "").upper(), 0)


def _gate_check(
    findings: List[Dict[str, Any]],
    threshold: str,
    ignore_rules: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Thin wrapper around cli.output.gate_check.check_gate."""
    from cli.output.gate_check import check_gate
    return check_gate(findings, threshold=threshold, ignore_rules=ignore_rules).to_dict()


def _write_output(data: Dict[str, Any], output_file: Optional[str]) -> None:
    payload = json.dumps(data, indent=2, default=str)
    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
        print(f"[secoraa] Wrote results to {output_file}", file=sys.stderr)
    else:
        print(payload)


def _sync_to_platform(
    platform_url: str,
    api_key: str,
    report: Dict[str, Any],
    gate: Dict[str, Any],
    args: argparse.Namespace,
) -> None:
    """POST scan results to the Secoraa platform CI sync endpoint."""
    import urllib.request
    import urllib.error

    url = platform_url.rstrip("/") + "/api/v1/ci/sync"

    findings_payload = []
    for f in report.get("findings") or []:
        findings_payload.append({
            "title": f.get("title") or f.get("finding_id") or "Unknown",
            "severity": f.get("severity", "INFORMATIONAL"),
            "owasp_category": f.get("owasp_category"),
            "endpoint": f.get("endpoint"),
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": f.get("cvss_vector"),
            "confidence": f.get("confidence"),
            "description": f.get("description"),
            "impact": f.get("impact"),
            "remediation": f.get("remediation"),
            "references": f.get("references"),
        })

    body = {
        "scan_name": report.get("scan_name") or "ci-scan",
        "scan_type": report.get("scan_type") or "API_SECURITY",
        "base_url": report.get("base_url") or "",
        "scan_mode": report.get("scan_mode"),
        "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"),
        "duration_seconds": report.get("duration_seconds"),
        "total_endpoints": report.get("total_endpoints", 0),
        "total_findings": len(findings_payload),
        "severity_counts": report.get("severity_counts"),
        "findings": findings_payload,
        "gate_passed": gate.get("passed"),
        "gate_threshold": gate.get("threshold"),
        "git_repo": os.environ.get("GITHUB_REPOSITORY"),
        "git_ref": os.environ.get("GITHUB_REF"),
        "git_sha": os.environ.get("GITHUB_SHA"),
        "pr_number": _parse_pr_number(),
    }

    data = json.dumps(body, default=str).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            print(
                f"[secoraa] Synced to platform: scan_id={result.get('scan_id')} "
                f"findings={result.get('findings_synced')}",
                file=sys.stderr,
            )
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(
            f"[secoraa] Platform sync failed (HTTP {exc.code}): {body_text[:200]}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"[secoraa] Platform sync failed: {exc}", file=sys.stderr)


def _parse_pr_number() -> Optional[int]:
    """Extract PR number from GITHUB_REF (refs/pull/123/merge)."""
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/pull/"):
        parts = ref.split("/")
        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                pass
    return None


def _print_summary(report: Dict[str, Any], gate: Dict[str, Any]) -> None:
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("  SECORAA SCAN SUMMARY", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Target:          {report.get('base_url') or report.get('domain') or 'n/a'}", file=sys.stderr)
    print(f"  Total endpoints: {report.get('total_endpoints', 'n/a')}", file=sys.stderr)
    print(f"  Total findings:  {report.get('total_findings', len(report.get('findings') or []))}", file=sys.stderr)
    counts = gate.get("severity_counts") or {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        if counts.get(sev):
            print(f"    {sev}: {counts[sev]}", file=sys.stderr)
    print(f"  Gate:            {gate.get('summary')}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


# ---------------------------------------------------------------------------
# API Scanner command
# ---------------------------------------------------------------------------
def _load_yaml_config(args: argparse.Namespace) -> Dict[str, Any]:
    """Load .secoraa.yml if present. Returns {} on missing or error."""
    from cli.config_loader import load_config, ConfigError
    config_path = getattr(args, "config", None)
    try:
        return load_config(config_path)
    except ConfigError as exc:
        print(f"[secoraa] config warning: {exc}", file=sys.stderr)
        return {}


def _resolve(
    cli_val: Optional[str],
    env_key: str,
    cfg: Dict[str, Any],
    cfg_path: List[str],
    default: Optional[str] = None,
) -> Optional[str]:
    """CLI > env > .secoraa.yml > default."""
    from cli.config_loader import resolve
    return resolve(cli_val, env_key, cfg, cfg_path, default)


def _cmd_api(args: argparse.Namespace) -> int:
    cfg = _load_yaml_config(args)

    target_url = _resolve(args.target_url, "TARGET_URL", cfg, ["scan", "target"])
    if not target_url:
        print("error: --target-url (or TARGET_URL env var) is required", file=sys.stderr)
        return EXIT_ERROR

    spec_path = _resolve(args.openapi_spec, "OPENAPI_SPEC_PATH", cfg, ["scan", "spec"])
    if not spec_path or spec_path == "auto":
        spec_path = _auto_detect_openapi_spec()
    if not spec_path:
        print(
            "error: no OpenAPI spec provided and none auto-detected. "
            "Pass --openapi-spec or set OPENAPI_SPEC_PATH.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        spec_data = _load_spec_file(spec_path)
    except Exception as exc:
        print(f"error: failed to load spec file '{spec_path}': {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Auth: CLI > env > .secoraa.yml (token_env resolves from env at runtime)
    from cli.config_loader import resolve_auth_token
    auth_token = _resolve(args.auth_token, "AUTH_TOKEN", cfg, ["scan", "auth", "token"])
    if not auth_token:
        auth_token = resolve_auth_token(cfg)
    auth_type = _resolve(args.auth_type, "AUTH_TYPE", cfg, ["scan", "auth", "type"], "bearer")
    try:
        auth_config = _build_auth_config(auth_token, auth_type)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    secondary_token = _env_or(args.secondary_token, "SECONDARY_TOKEN")
    try:
        secondary_auth_config = _build_auth_config(secondary_token, auth_type) if secondary_token else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    scan_mode = _resolve(args.scan_mode, "SCAN_MODE", cfg, ["scan", "mode"], "active") or "active"
    scan_name = _resolve(args.scan_name, "", cfg, ["scan", "name"]) or f"cli-scan-{target_url.replace('://', '-').replace('/', '-')}"

    print(f"[secoraa] Starting API scan: {target_url}", file=sys.stderr)
    print(f"[secoraa] Spec: {spec_path}", file=sys.stderr)
    print(f"[secoraa] Mode: {scan_mode}", file=sys.stderr)
    if auth_config:
        print(f"[secoraa] Auth: {auth_config.get('type')}", file=sys.stderr)

    # Import here so the CLI doesn't pull heavy deps unless the user runs a scan
    try:
        from app.scanners.api_scanner.main import run_api_scan
    except ImportError as exc:
        print(f"error: failed to import scanner engine: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        report = asyncio.run(
            run_api_scan(
                scan_name=scan_name,
                asset_url=target_url,
                openapi_spec=spec_data,
                auth_config=auth_config,
                secondary_auth_config=secondary_auth_config,
                scan_mode=scan_mode,
                db=None,
                scan_id=None,
            )
        )
    except Exception as exc:
        logger.exception("Scan failed")
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = report.get("findings") or []
    threshold = _resolve(args.severity_threshold, "SEVERITY_THRESHOLD", cfg, ["gate", "severity_threshold"], "HIGH") or "HIGH"
    # ignore_rules: CLI (comma string) > env (comma string) > .secoraa.yml (list)
    ignore_rules_raw = _env_or(args.ignore_rules, "IGNORE_RULES")
    if ignore_rules_raw:
        ignore_rules = [r.strip() for r in ignore_rules_raw.split(",") if r.strip()]
    else:
        yml_ignore = (cfg.get("gate") or {}).get("ignore_rules")
        ignore_rules = list(yml_ignore) if isinstance(yml_ignore, list) else None
    gate = _gate_check(findings, threshold, ignore_rules=ignore_rules)

    output_format = _resolve(args.output_format, "OUTPUT_FORMAT", cfg, ["report", "format"], "json") or "json"
    output_format = output_format.lower()
    output_file = _resolve(args.output_file, "OUTPUT_FILE", cfg, ["report", "output_file"])

    if output_format == "sarif":
        try:
            from cli.output.sarif_formatter import generate_sarif
        except ImportError as exc:
            print(f"error: failed to import SARIF formatter: {exc}", file=sys.stderr)
            return EXIT_ERROR
        sarif_doc = generate_sarif(report)
        _write_output(sarif_doc, output_file)
    else:
        # Default: JSON
        payload = {
            "scan": report,
            "gate": gate,
        }
        _write_output(payload, output_file)
    _print_summary(report, gate)

    # --- PR comment (GitHub Actions only) ------------------------------------
    pr_comment = _resolve(getattr(args, "pr_comment", None), "PR_COMMENT", cfg, ["report", "pr_comment"], "true")
    if str(pr_comment or "true").lower() in ("1", "true", "yes"):
        try:
            from cli.output.pr_comment import post_pr_comment
            post_pr_comment(report, gate)
        except Exception as exc:
            print(f"[secoraa] PR comment error: {exc}", file=sys.stderr)

    # --- Sync to Secoraa platform (optional) --------------------------------
    sync_url = _resolve(getattr(args, "sync_url", None), "SECORAA_URL", cfg, ["platform", "url"])
    sync_token = _resolve(getattr(args, "sync_token", None), "SECORAA_API_KEY", cfg, ["platform", "api_key"])
    if sync_url and sync_token:
        _sync_to_platform(sync_url, sync_token, report, gate, args)

    fail_val = _resolve(args.fail_on_findings, "FAIL_ON_FINDINGS", cfg, ["gate", "fail_on_findings"], "true")
    fail_on_findings = str(fail_val or "true").lower() in ("1", "true", "yes")
    if not gate["passed"] and fail_on_findings:
        return EXIT_GATE_FAILED
    return EXIT_PASS


# ---------------------------------------------------------------------------
# Subdomain Scanner command
# ---------------------------------------------------------------------------
def _cmd_subdomain(args: argparse.Namespace) -> int:
    domain = _env_or(args.domain, "SCAN_DOMAIN")
    if not domain:
        print("error: --domain (or SCAN_DOMAIN env var) is required", file=sys.stderr)
        return EXIT_ERROR

    subdomains_raw = _env_or(args.subdomains, "SCAN_SUBDOMAINS")
    subdomains: Optional[List[str]] = None
    if subdomains_raw:
        subdomains = [s.strip() for s in subdomains_raw.split(",") if s.strip()]

    print(f"[secoraa] Starting subdomain scan: {domain}", file=sys.stderr)
    if subdomains:
        print(f"[secoraa] Selected subdomains: {subdomains}", file=sys.stderr)

    try:
        from app.scanners.subdomain_scanner.scanner import SubdomainScanner
    except ImportError as exc:
        print(f"error: failed to import subdomain scanner: {exc}", file=sys.stderr)
        return EXIT_ERROR

    payload = {
        "domain": domain,
        "subdomains": subdomains,
        "tenant": os.environ.get("SECORAA_TENANT", "cli"),
    }

    try:
        result = SubdomainScanner().run(payload)
    except Exception as exc:
        logger.exception("Subdomain scan failed")
        print(f"error: subdomain scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Extract findings from the nested report structure
    report = result.get("report") or {}
    findings = []
    if isinstance(report, dict):
        findings = report.get("vulnerabilities") or report.get("findings") or []

    threshold = _env_or(args.severity_threshold, "SEVERITY_THRESHOLD", "HIGH") or "HIGH"
    ignore_rules_raw = _env_or(getattr(args, "ignore_rules", None), "IGNORE_RULES")
    ignore_rules = [r.strip() for r in ignore_rules_raw.split(",") if r.strip()] if ignore_rules_raw else None
    gate = _gate_check(findings, threshold, ignore_rules=ignore_rules)

    output_file = _env_or(args.output_file, "OUTPUT_FILE")
    payload_out = {
        "scan": result,
        "gate": gate,
    }
    _write_output(payload_out, output_file)

    # Normalize for the summary printer
    summary_report = {
        "domain": domain,
        "total_endpoints": result.get("total_found"),
        "total_findings": len(findings),
        "findings": findings,
    }
    _print_summary(summary_report, gate)

    fail_on_findings = (_env_or(args.fail_on_findings, "FAIL_ON_FINDINGS", "false") or "false").lower() in ("1", "true", "yes")
    if not gate["passed"] and fail_on_findings:
        return EXIT_GATE_FAILED
    return EXIT_PASS


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secoraa-scanner",
        description="Secoraa Scanner CLI — run API and Subdomain scanners from the command line.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--config", help="Path to .secoraa.yml config file (auto-detected if omitted)", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    # --- api subcommand ---
    api = sub.add_parser("api", help="Run the API APT scanner")
    api.add_argument("--target-url", help="API base URL to scan (env: TARGET_URL)")
    api.add_argument("--openapi-spec", help="Path to OpenAPI/Swagger spec file (env: OPENAPI_SPEC_PATH). Use 'auto' to auto-detect.")
    api.add_argument("--auth-token", help="Auth token (env: AUTH_TOKEN)")
    api.add_argument("--auth-type", help="Auth type: bearer | api_key | basic (env: AUTH_TYPE)", default=None)
    api.add_argument("--secondary-token", help="Second low-privilege token for BOLA/BFLA (env: SECONDARY_TOKEN)")
    api.add_argument("--scan-mode", help="Scan mode: active | passive (env: SCAN_MODE)", default=None)
    api.add_argument("--scan-name", help="Optional scan name", default=None)
    api.add_argument("--output-format", help="Output format: json | sarif (env: OUTPUT_FORMAT)", default=None)
    api.add_argument("--output-file", help="Write output to this file instead of stdout (env: OUTPUT_FILE)")
    api.add_argument("--severity-threshold", help="Gate threshold: CRITICAL | HIGH | MEDIUM | LOW (env: SEVERITY_THRESHOLD)", default=None)
    api.add_argument("--ignore-rules", help="Comma-separated OWASP categories to ignore (env: IGNORE_RULES)", default=None)
    api.add_argument("--fail-on-findings", help="Exit 1 if findings >= threshold (env: FAIL_ON_FINDINGS)", default=None)
    api.add_argument("--sync-url", help="Secoraa platform URL to sync results (env: SECORAA_URL)", default=None)
    api.add_argument("--sync-token", help="Secoraa API key for sync (env: SECORAA_API_KEY)", default=None)
    api.add_argument("--pr-comment", help="Post scan summary as PR comment (env: PR_COMMENT)", default=None)
    api.set_defaults(func=_cmd_api)

    # --- subdomain subcommand ---
    sd = sub.add_parser("subdomain", help="Run the Subdomain/Vulnerability scanner")
    sd.add_argument("--domain", help="Root domain to scan (env: SCAN_DOMAIN)")
    sd.add_argument("--subdomains", help="Comma-separated list of specific subdomains (env: SCAN_SUBDOMAINS)")
    sd.add_argument("--output-file", help="Write output to this file instead of stdout (env: OUTPUT_FILE)")
    sd.add_argument("--severity-threshold", help="Gate threshold (env: SEVERITY_THRESHOLD)", default=None)
    sd.add_argument("--ignore-rules", help="Comma-separated rule ids to ignore (env: IGNORE_RULES)", default=None)
    sd.add_argument("--fail-on-findings", help="Exit 1 if findings >= threshold (env: FAIL_ON_FINDINGS)", default=None)
    sd.set_defaults(func=_cmd_subdomain)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[secoraa] Interrupted by user", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover
        logger.exception("CLI error")
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
