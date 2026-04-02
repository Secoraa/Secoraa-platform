from __future__ import annotations

import logging
import re
from typing import Set

import requests

logger = logging.getLogger(__name__)


def fetch_from_crtsh(domain: str) -> Set[str]:
    """Fetch subdomains from crt.sh (certificate transparency logs)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: Set[str] = set()

    try:
        response = requests.get(url, timeout=25)
        if response.status_code != 200:
            logger.warning("crt.sh returned status %d for %s", response.status_code, domain)
            return subdomains

        data = response.json()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(domain.lower()):
                        subdomains.add(sub)

        logger.info("crt.sh found %d subdomains for %s", len(subdomains), domain)
    except Exception as exc:
        logger.warning("crt.sh fetch failed for %s: %s", domain, exc)

    return subdomains


def fetch_from_hackertarget(domain: str) -> Set[str]:
    """Fetch subdomains from HackerTarget (free, no API key)."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: Set[str] = set()

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            logger.warning("HackerTarget returned status %d for %s", response.status_code, domain)
            return subdomains

        text = response.text.strip()
        if text.startswith("error") or not text:
            return subdomains

        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith(domain.lower()):
                    subdomains.add(sub)

        logger.info("HackerTarget found %d subdomains for %s", len(subdomains), domain)
    except Exception as exc:
        logger.warning("HackerTarget fetch failed for %s: %s", domain, exc)

    return subdomains


def fetch_from_alienvault(domain: str) -> Set[str]:
    """Fetch subdomains from AlienVault OTX passive DNS (free, no API key)."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains: Set[str] = set()

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            logger.warning("AlienVault returned status %d for %s", response.status_code, domain)
            return subdomains

        data = response.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lower()
            if hostname.endswith(domain.lower()):
                subdomains.add(hostname)

        logger.info("AlienVault found %d subdomains for %s", len(subdomains), domain)
    except Exception as exc:
        logger.warning("AlienVault fetch failed for %s: %s", domain, exc)

    return subdomains


def fetch_from_rapiddns(domain: str) -> Set[str]:
    """Fetch subdomains from RapidDNS (free, no API key)."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains: Set[str] = set()

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if response.status_code != 200:
            logger.warning("RapidDNS returned status %d for %s", response.status_code, domain)
            return subdomains

        pattern = r"(?:[\w-]+\.)+?" + re.escape(domain.lower())
        matches = re.findall(pattern, response.text.lower())
        for m in matches:
            m = m.strip().lstrip("*.")
            if m.endswith(domain.lower()):
                subdomains.add(m)

        logger.info("RapidDNS found %d subdomains for %s", len(subdomains), domain)
    except Exception as exc:
        logger.warning("RapidDNS fetch failed for %s: %s", domain, exc)

    return subdomains


def fetch_all_passive(domain: str) -> Set[str]:
    """
    Run all passive subdomain discovery sources in sequence.
    Each source is independent — one failure does not block others.
    """
    results: Set[str] = set()

    for fetcher in [fetch_from_crtsh, fetch_from_hackertarget,
                    fetch_from_alienvault, fetch_from_rapiddns]:
        try:
            found = fetcher(domain)
            results.update(found)
        except Exception as exc:
            logger.error("Passive source %s failed: %s", fetcher.__name__, exc)

    # Normalize: lowercase, strip wildcards, ensure it belongs to the domain
    cleaned: Set[str] = set()
    for s in results:
        s = s.strip().lower().lstrip("*.")
        if s and s.endswith(domain.lower()):
            cleaned.add(s)

    logger.info("Total passive discovery: %d unique subdomains for %s", len(cleaned), domain)
    return cleaned
