# parser/postman_parser.py
from typing import List, Dict

def parse_postman(collection: Dict) -> List[Dict]:
    """
    Extract endpoints from Postman collection
    """
    endpoints = []

    def walk(items):
        for item in items:
            if "request" in item:
                req = item["request"]
                url = req.get("url", {})
                path = "/" + "/".join(url.get("path", []))

                endpoints.append({
                    "name": item.get("name"),
                    "method": req.get("method"),
                    "path": path,
                    "headers": req.get("header", []),
                    "body": req.get("body", {})
                })
            elif "item" in item:
                walk(item["item"])

    walk(collection.get("item", []))
    return endpoints
