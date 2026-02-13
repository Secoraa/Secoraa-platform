from typing import Tuple, Optional

import requests


def check_reachability(domain: str, timeout: int) -> Tuple[bool, Optional[requests.Response], Optional[str]]:
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    try:
        response = requests.get(https_url, timeout=timeout, allow_redirects=True)
        return True, response, response.url
    except requests.RequestException:
        pass

    try:
        response = requests.get(http_url, timeout=timeout, allow_redirects=True)
        return True, response, response.url
    except requests.RequestException:
        return False, None, None
