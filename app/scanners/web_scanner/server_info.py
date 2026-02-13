from typing import Dict


def extract_server_info(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        "server": headers.get("server", ""),
        "x-powered-by": headers.get("x-powered-by", ""),
        "x-aspnet-version": headers.get("x-aspnet-version", ""),
    }
