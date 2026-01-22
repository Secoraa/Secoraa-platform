# tests/bola_tests.py


from app.scanners.api_scanner.engine.request_executor import execute_request
from urllib.parse import urljoin


async def test_bola(endpoint, base_url):
    if "{id}" not in endpoint["path"]:
        return None

    test_path = endpoint["path"].replace("{id}", "999999")
    url = urljoin(base_url.rstrip("/") + "/", str(test_path).lstrip("/"))

    response = await execute_request(
        endpoint["method"],
        url
    )

    if response.status_code == 200:
        return {
            "issue": "Broken Object Level Authorization (BOLA)",
            "severity": "HIGH",
            "endpoint": endpoint["path"]
        }

    return None
