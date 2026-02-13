from collections import deque
from typing import List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from app.scanners.web_scanner.utils.helpers import is_same_domain, should_skip_url


def crawl(start_url: str, max_depth: int, max_pages: int, timeout: int) -> List[str]:
    visited = set()
    queue = deque([(start_url, 0)])

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=timeout)
        except requests.RequestException:
            continue

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link.get("href", "").strip()
            if not href:
                continue
            normalized = urljoin(current_url, href)
            parsed = urlparse(normalized)
            if parsed.scheme not in ("http", "https"):
                continue
            if should_skip_url(parsed.path):
                continue
            if not is_same_domain(start_url, normalized):
                continue
            if normalized not in visited:
                queue.append((normalized, depth + 1))

    return list(visited)
