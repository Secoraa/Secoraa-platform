from typing import Dict, Any, List


def evaluate_tls(tls_info: Dict[str, Any]) -> List[str]:
    findings = []
    version = (tls_info.get("tls_version") or "").upper()
    if version and ("TLSV1" in version or "SSLV" in version):
        if version not in ("TLSV1.2", "TLSV1.3"):
            findings.append("httpsCertificateVersion")
    if tls_info.get("is_wildcard"):
        findings.append("wildcardTLSCertificate")
    return findings
