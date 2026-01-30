import socket
from datetime import datetime
from app.scanners.base import BaseScanner

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}


def tcp_connect_scan(target_ip, timeout=1):
    scan_result = {
        "target": target_ip,
        "scan_time": datetime.utcnow().isoformat(),
        "open_ports": [],
    }

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()

            if result == 0:
                scan_result["open_ports"].append(
                    {
                        "port": port,
                        "service": service,
                    }
                )
        except Exception:
            pass

    return scan_result


class NetworkScanner(BaseScanner):
    name = "network"

    def run(self, payload: dict) -> dict:
        target_ip = (payload.get("target_ip") or payload.get("ip") or "").strip()
        if not target_ip:
            raise ValueError("target_ip is required")

        result = tcp_connect_scan(target_ip)
        return {
            "scan_type": self.name,
            "target": target_ip,
            "open_ports": result.get("open_ports", []),
            "scan_time": result.get("scan_time"),
        }
