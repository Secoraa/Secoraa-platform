from typing import Optional


def evaluate_redirect(http_final_url: Optional[str]) -> Optional[str]:
    if not http_final_url:
        return "lackingRedirectHttpHttps"
    if not http_final_url.lower().startswith("https://"):
        return "lackingRedirectHttpHttps"
    return None
