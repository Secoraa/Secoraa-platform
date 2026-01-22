from typing import List

COMMON_WORDS = [
    "www", "api", "admin", "dev", "test",
    "staging", "beta", "mail", "blog",
    "dashboard", "portal", "internal"
]


def bruteforce_subdomains(domain: str) -> List[str]:
    """
    Generate possible subdomains using wordlist
    """
    return [f"{word}.{domain}" for word in COMMON_WORDS]
