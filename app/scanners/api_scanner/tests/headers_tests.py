# tests/headers_tests.py

def test_security_headers(response, endpoint):
    missing = []

    required = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options"
    ]

    for header in required:
        if header not in response.headers:
            missing.append(header)

    if missing:
        return {
            "issue": "Missing Security Headers",
            "severity": "MEDIUM",
            "missing_headers": missing,
            "endpoint": endpoint["path"]
        }

    return None
