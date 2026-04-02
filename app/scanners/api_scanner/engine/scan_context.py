from __future__ import annotations

import uuid


class ScanContext:
    """Per-scan context with randomized markers to avoid WAF fingerprinting."""

    def __init__(self):
        self._nonce = uuid.uuid4().hex[:8]

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def cmd_marker(self) -> str:
        """Unique marker for command injection output detection."""
        return f"SCNR{self._nonce}"

    @property
    def invalid_token(self) -> str:
        """Random invalid token for auth bypass testing."""
        return f"inv_{uuid.uuid4().hex}"

    @property
    def invalid_api_key(self) -> str:
        """Random invalid API key for auth bypass testing."""
        return f"key_{uuid.uuid4().hex}"

    @property
    def evil_origin(self) -> str:
        """Random evil origin for CORS testing."""
        return f"https://{self._nonce}-test.example.com"

    @property
    def baseline_domain(self) -> str:
        """Random nonexistent domain for SSRF baseline."""
        return f"http://{self._nonce}-baseline.invalid"
