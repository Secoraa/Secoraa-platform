from typing import Dict, Any

from app.scanners.web_scanner.context import ScanContext


def build_report(context: ScanContext) -> Dict[str, Any]:
    return {
        "scan": context.scan,
        "preflight_checks": context.preflight_checks,
        "findings_metadata": context.findings_metadata,
        "messages": context.messages,
        "findings": context.findings,
        "files": context.files,
        "secrets": context.secrets,
    }
