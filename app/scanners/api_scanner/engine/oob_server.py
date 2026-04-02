from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Configure via env vars or fall back to defaults
DEFAULT_OOB_PORT = int(os.getenv("OOB_PORT", "9999"))
DEFAULT_OOB_HOST = os.getenv("OOB_HOST", "0.0.0.0")
# External URL that targets will call back to (must be reachable from the target)
# e.g. http://<your-public-ip>:9999 or an ngrok/tunnel URL
DEFAULT_OOB_BASE = os.getenv("OOB_BASE_URL", "")


@dataclass
class OOBInteraction:
    token: str
    scan_id: str
    test_type: str  # ssrf, xxe, cmdi, sqli
    endpoint: str
    payload: str
    source_ip: Optional[str] = None
    timestamp: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    path: Optional[str] = None


class OOBCallbackServer:
    """Lightweight async HTTP server that records OOB interactions."""

    def __init__(self, host: str = DEFAULT_OOB_HOST, port: int = DEFAULT_OOB_PORT):
        self.host = host
        self.port = port
        self._interactions: List[OOBInteraction] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False

    async def start(self):
        """Start the OOB callback listener."""
        if self._running:
            return

        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port,
        )
        self._running = True
        logger.info("OOB callback server listening on %s:%d", self.host, self.port)

    async def stop(self):
        """Stop the OOB callback listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._running = False
            logger.info("OOB callback server stopped")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming OOB callback."""
        try:
            # Read the HTTP request line and headers
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            request_str = request_line.decode("utf-8", errors="replace").strip()

            headers_raw = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    key, val = line_str.split(":", 1)
                    headers_raw[key.strip()] = val.strip()

            # Parse request
            parts = request_str.split(" ")
            http_method = parts[0] if parts else "UNKNOWN"
            req_path = parts[1] if len(parts) > 1 else "/"

            # Extract token from path: /oob/<token> or /oob/xxe-dtd/<token>
            token = ""
            if "/oob/" in req_path:
                token = req_path.split("/oob/")[-1].split("?")[0].split("/")[0]

            # Get source IP
            peername = writer.get_extra_info("peername")
            source_ip = peername[0] if peername else "unknown"

            interaction = OOBInteraction(
                token=token,
                scan_id="",  # filled by tracker
                test_type=_extract_test_type(token),
                endpoint="",  # filled by tracker
                payload="",
                source_ip=source_ip,
                timestamp=datetime.utcnow().isoformat(),
                method=http_method,
                headers=headers_raw,
                path=req_path,
            )
            self._interactions.append(interaction)
            logger.info("OOB callback received: %s %s from %s (token=%s)", http_method, req_path, source_ip, token)

            # Send minimal HTTP response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n"
                "\r\n"
                "ok"
            )
            writer.write(response.encode())
            await writer.drain()
        except Exception as exc:
            logger.debug("OOB handler error: %s", exc)
        finally:
            writer.close()

    def get_interactions(self, token: Optional[str] = None) -> List[OOBInteraction]:
        """Get recorded interactions, optionally filtered by token prefix."""
        if token is None:
            return list(self._interactions)
        return [i for i in self._interactions if i.token.startswith(token)]

    def clear(self):
        """Clear all recorded interactions."""
        self._interactions.clear()


def _extract_test_type(token: str) -> str:
    """Extract test type from token format: <scan_id>-<type>-<random>."""
    parts = token.split("-")
    if len(parts) >= 2:
        return parts[1]  # e.g., "ssrf", "xxe", "cmdi", "sqli"
    return "unknown"


# ── Singleton callback server (shared across scans) ─────────────────────
_callback_server: Optional[OOBCallbackServer] = None


async def get_callback_server() -> OOBCallbackServer:
    """Get or create the singleton OOB callback server."""
    global _callback_server
    if _callback_server is None:
        _callback_server = OOBCallbackServer()
        await _callback_server.start()
    return _callback_server


class OOBTracker:
    """Track OOB tokens and interactions for a scan."""

    def __init__(
        self,
        scan_id: str,
        oob_base_url: str = DEFAULT_OOB_BASE,
        callback_server: Optional[OOBCallbackServer] = None,
    ):
        self.scan_id = scan_id
        self.oob_base_url = oob_base_url.rstrip("/") if oob_base_url else ""
        self._tokens: Dict[str, Dict[str, Any]] = {}  # token -> metadata
        self._callback_server = callback_server
        self._enabled = bool(self.oob_base_url)

        if not self._enabled:
            logger.info(
                "OOB detection disabled — set OOB_BASE_URL env var to enable "
                "(e.g. http://<your-ip>:%d)", DEFAULT_OOB_PORT,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def generate_token(self, test_type: str, endpoint: str, payload_desc: str) -> str:
        """Generate a unique OOB token and register its metadata."""
        short_id = self.scan_id[:8] if len(self.scan_id) > 8 else self.scan_id
        random_suffix = uuid.uuid4().hex[:6]
        token = f"{short_id}-{test_type}-{random_suffix}"
        self._tokens[token] = {
            "test_type": test_type,
            "endpoint": endpoint,
            "payload_desc": payload_desc,
        }
        return token

    def get_callback_url(self, token: str) -> str:
        """Get the full callback URL for a token."""
        return f"{self.oob_base_url}/oob/{token}"

    def generate_payload_url(self, test_type: str, endpoint: str, payload_desc: str) -> str:
        """Convenience: generate token and return callback URL in one step."""
        token = self.generate_token(test_type, endpoint, payload_desc)
        return self.get_callback_url(token)

    def record_interaction(self, interaction: OOBInteraction):
        """Record an OOB interaction manually."""
        interaction.scan_id = self.scan_id
        if interaction.token in self._tokens:
            meta = self._tokens[interaction.token]
            interaction.endpoint = meta.get("endpoint", "")

    def get_token_count(self) -> int:
        """Get total number of generated tokens."""
        return len(self._tokens)

    async def check_for_interactions(self) -> List[OOBInteraction]:
        """
        Check for OOB interactions by querying the callback server.
        Returns interactions that match tokens generated by this tracker.
        """
        if not self._enabled:
            return []

        interactions: List[OOBInteraction] = []

        # Check local callback server
        if self._callback_server:
            short_id = self.scan_id[:8] if len(self.scan_id) > 8 else self.scan_id
            raw = self._callback_server.get_interactions(short_id)
            for interaction in raw:
                # Enrich with metadata from registered tokens
                if interaction.token in self._tokens:
                    meta = self._tokens[interaction.token]
                    interaction.scan_id = self.scan_id
                    interaction.endpoint = meta.get("endpoint", "")
                    interaction.test_type = meta.get("test_type", interaction.test_type)
                    interactions.append(interaction)

        logger.debug(
            "OOB check: %d interactions found for scan %s (%d tokens registered)",
            len(interactions), self.scan_id[:8], len(self._tokens),
        )
        return interactions

    def has_interactions(self) -> bool:
        """Quick check if any OOB interactions were recorded."""
        if self._callback_server:
            short_id = self.scan_id[:8] if len(self.scan_id) > 8 else self.scan_id
            return len(self._callback_server.get_interactions(short_id)) > 0
        return False
