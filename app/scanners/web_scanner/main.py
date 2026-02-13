import argparse
import logging

from app.scanners.web_scanner.config import DEFAULTS
from app.scanners.web_scanner.scanner import run_scan


logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def _parse_args():
    parser = argparse.ArgumentParser(description="Secoraa Web Security Scanner")
    parser.add_argument("domain", help="Domain or subdomain to scan")
    parser.add_argument("--depth", type=int, default=DEFAULTS["depth"])
    parser.add_argument("--pages", type=int, default=DEFAULTS["pages"])
    parser.add_argument("--timeout", type=int, default=DEFAULTS["timeout"])
    parser.add_argument("--output", type=str, default="report.json")
    return parser.parse_args()


def main():
    args = _parse_args()
    report = run_scan(args.domain, depth=args.depth, pages=args.pages, timeout=args.timeout)
    with open(args.output, "w", encoding="utf-8") as file:
        import json

        json.dump(report, file, indent=2)


if __name__ == "__main__":
    main()
