# reporter/report_generator.py
from datetime import datetime

def generate_report(scan_name, endpoints, findings):
    return {
        "scan_name": scan_name,
        "scan_type": "API_SECURITY",
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
        "generated_at": datetime.utcnow().isoformat(),
        "findings": findings
    }
