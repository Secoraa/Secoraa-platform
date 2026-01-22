# tests/auth_tests.py


from app.scanners.api_scanner.engine.request_executor import execute_request
from urllib.parse import urljoin


async def test_missing_auth(endpoint, base_url):
    url = urljoin(base_url.rstrip("/") + "/", str(endpoint.get("path", "")).lstrip("/"))

    response = await execute_request(
        endpoint["method"],
        url
    )

    if response.status_code == 200:
        return {
            "issue": "Missing Authentication",
            "severity": "HIGH",
            "endpoint": endpoint["path"]
        }

    return None
