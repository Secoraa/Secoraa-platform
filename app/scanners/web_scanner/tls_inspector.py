from typing import Dict, Any
import socket
import ssl


def inspect_tls(domain: str, timeout: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            result["tls_version"] = ssock.version()
            result["cipher"] = ssock.cipher()
            result["issuer"] = cert.get("issuer", [])
            result["subject"] = cert.get("subject", [])
            result["notAfter"] = cert.get("notAfter", "")
            result["notBefore"] = cert.get("notBefore", "")
            result["subjectAltName"] = cert.get("subjectAltName", [])
            result["is_wildcard"] = any(
                isinstance(entry, tuple) and entry[1].startswith("*.") for entry in cert.get("subjectAltName", [])
            )
    return result
