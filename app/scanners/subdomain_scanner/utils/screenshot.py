# app/scanners/subdomain_scanner/utils/screenshot.py

from playwright.sync_api import sync_playwright
import os


def capture_screenshot(url: str, output_dir="screenshots"):
    os.makedirs(output_dir, exist_ok=True)
    filename = url.replace("://", "_").replace("/", "_") + ".png"
    path = os.path.join(output_dir, filename)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url, timeout=10000)
        page.screenshot(path=path)
        browser.close()

    return path
