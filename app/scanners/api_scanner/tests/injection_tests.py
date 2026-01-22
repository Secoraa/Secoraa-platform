# tests/injection_tests.py


from app.scanners.api_scanner.engine.request_executor import execute_request
from urllib.parse import urljoin


async def test_nosql_injection(endpoint, base_url):
    if endpoint["method"] != "POST":
        return None

    payload = {"$ne": None}
    url = urljoin(base_url.rstrip("/") + "/", str(endpoint.get("path", "")).lstrip("/"))

    response = await execute_request(
        endpoint["method"],
        url,
        body=payload
    )

    if response.status_code == 200:
        return {
            "issue": "Possible NoSQL Injection",
            "severity": "HIGH",
            "endpoint": endpoint["path"]
        }

    return None
