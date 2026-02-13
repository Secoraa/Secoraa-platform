from typing import Dict


def extract_headers(response) -> Dict[str, str]:
    headers = {}
    if not response:
        return headers
    for key, value in response.headers.items():
        headers[key.lower()] = value
    return headers
