from typing import Dict, Any, Optional

import requests

from app.scanners.web_scanner.config import DEFAULTS
from app.scanners.web_scanner.context import ScanContext
from app.scanners.web_scanner.reachability import check_reachability
from app.scanners.web_scanner.header_analyzer import extract_headers
from app.scanners.web_scanner.cache_analyzer import analyze_cache_headers
from app.scanners.web_scanner.server_info import extract_server_info
from app.scanners.web_scanner.tls_inspector import inspect_tls
from app.scanners.web_scanner.crawler import crawl
from app.scanners.web_scanner.finding_builder import build_finding
from app.scanners.web_scanner.report_builder import build_report
from app.scanners.web_scanner.rules.header_rules import evaluate_headers
from app.scanners.web_scanner.rules.redirect_rules import evaluate_redirect
from app.scanners.web_scanner.rules.tls_rules import evaluate_tls
from app.scanners.web_scanner.rules.cache_rules import evaluate_cache
from app.scanners.web_scanner.utils.helpers import generate_uuid, normalize_domain


def run_scan(
    domain: str,
    tenant: Optional[str] = None,
    depth: int = DEFAULTS["depth"],
    pages: int = DEFAULTS["pages"],
    timeout: int = DEFAULTS["timeout"],
) -> Dict[str, Any]:
    context = ScanContext()
    tenant_value = tenant or "default"
    execution_id = generate_uuid()
    normalized_domain = normalize_domain(domain)

    context.scan = {
        "domain": normalized_domain,
        "asset_uuid": generate_uuid(),
        "asset_value": normalized_domain,
        "asset_type": "Subdomain",
        "is_extensive_scan": False,
        "is_invasive": False,
        "tenant": tenant_value,
        "execution_id": execution_id,
    }

    context.messages["infos"].append("Scan started")

    reachable, response, final_url = check_reachability(normalized_domain, timeout)
    context.preflight_checks = {
        "reachable": reachable,
        "status_code": response.status_code if response else None,
        "final_url": final_url,
    }

    if reachable:
        context.messages["infos"].append("The asset is reachable.")
        context.detected_headers = extract_headers(response)
        cache_headers = analyze_cache_headers(context.detected_headers)
        server_info = extract_server_info(context.detected_headers)
    else:
        context.messages["errors"].append("DNS failure or unreachable asset.")
        cache_headers = {}
        server_info = {}

    context.messages["infos"].append("This is a BlackBox scan")

    http_final_url = None
    if reachable:
        try:
            http_response = requests.get(f"http://{normalized_domain}", timeout=timeout, allow_redirects=True)
            http_final_url = http_response.url
        except requests.RequestException:
            context.messages["warnings"].append("Timeout")
            http_final_url = None

    try:
        context.tls_info = inspect_tls(normalized_domain, timeout)
    except Exception:
        context.messages["errors"].append("SSL error")
        context.tls_info = {}

    start_url = final_url if final_url else f"https://{normalized_domain}"
    crawled_urls = crawl(start_url, depth, pages, timeout) if reachable else []
    context.crawled_urls = crawled_urls
    context.findings_metadata["crawlUrls"]["unauthenticatedUrl"] = crawled_urls
    context.findings_metadata["totalCrawlUrls"] = len(crawled_urls)
    context.messages["totalCrawledUrls"] = len(crawled_urls)

    # Rule engine
    vuln_keys = []
    vuln_keys.extend(evaluate_headers(context.detected_headers))

    redirect_vuln = evaluate_redirect(http_final_url)
    if redirect_vuln:
        vuln_keys.append(redirect_vuln)

    vuln_keys.extend(evaluate_tls(context.tls_info))

    cache_vuln = evaluate_cache(cache_headers)
    if cache_vuln:
        vuln_keys.append(cache_vuln)

    if server_info.get("server") or server_info.get("x-powered-by") or server_info.get("x-aspnet-version"):
        vuln_keys.append("serverDetails")

    for vuln_key in vuln_keys:
        finding = build_finding(vuln_key, execution_id, tenant_value, crawled_urls[:5])
        context.findings.append(finding)

    context.messages["infos"].append("Scan completed")
    return build_report(context)
