"""Epoch weight poster: deterministic HTTPS POST with HMAC-SHA256 binding.

Posts completed epoch weights to a remote endpoint. Provides idempotent retry
semantics via digest matching, deterministic JSON serialization, mandatory bearer
token + HMAC-SHA256 authentication, and hard caps on response size and wall-clock time.

See docs/DESIGN.md §10.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import select
import time
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PosterError(Exception):
    """Raised on network, auth, or protocol failures."""


# ---------------------------------------------------------------------------
# Poster
# ---------------------------------------------------------------------------

class Poster:
    """Post epoch weights with HMAC-SHA256 binding and strict timeout/response caps.

    Serializes weights deterministically (sorted keys, stable order), computes
    a SHA256 digest of the JSON payload, and signs it with HMAC-SHA256 using
    the provided secret. Sends as HTTPS (or HTTP in test mode) with a bearer
    token and mandatory signature header.

    Idempotent: reposting the same digest (via retry) with the same secret
    succeeds without error; mismatched digests are rejected by the server.
    """

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        secret: str,
        timeout_seconds: float = 30.0,
        response_cap_bytes: int = 1024 * 1024,
        test_mode: bool = False,
    ) -> None:
        """Initialize a poster instance.

        :param endpoint:         Remote URL (e.g., "https://validator.example.com/epochs")
        :param bearer_token:     Bearer token for Authorization header
        :param secret:           Shared secret for HMAC-SHA256 signature
        :param timeout_seconds:  Wall-clock timeout for request+response (default 30s)
        :param response_cap_bytes: Max response body size before aborting (default 1 MiB)
        :param test_mode:        If True, allow HTTP (no HTTPS requirement)
        """
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.response_cap_bytes = response_cap_bytes
        self.test_mode = test_mode

    def post(self, weights: dict[str, float], digest: str | None = None) -> dict[str, Any]:
        """POST epoch weights to the remote endpoint.

        Returns the parsed JSON response dict from the server.

        :param weights:         {hotkey: score} dict to post
        :param digest:          Pre-computed SHA256 digest (or None to recompute)
                                Used for idempotent retries with same payload.

        Raises :class:`PosterError` on network, auth, timeout, or response cap exceeded.
        """
        if digest is None:
            digest = self._compute_digest(weights)

        payload_json = self._serialize_weights(weights)
        signature = self._hmac_sha256(payload_json)

        try:
            response_text = self._send_request(
                payload_json,
                signature,
                digest,
            )
        except Exception as exc:
            raise PosterError(f"POST to {self.endpoint} failed: {exc}") from exc

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise PosterError(f"Invalid JSON response from {self.endpoint}: {exc}") from exc

    def _serialize_weights(self, weights: dict[str, float]) -> str:
        """Deterministic JSON serialization with sorted keys.

        Produces the exact same JSON for the same input dict, enabling
        consistent digest computation across retries.
        """
        # Sort keys for determinism; use separators with no spaces
        return json.dumps(weights, sort_keys=True, separators=(",", ":"))

    def _compute_digest(self, weights: dict[str, float]) -> str:
        """SHA256 digest of the serialized JSON payload (hex format)."""
        payload = self._serialize_weights(weights)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _hmac_sha256(self, payload_json: str) -> str:
        """HMAC-SHA256 signature of the payload (hex format)."""
        sig_bytes = hmac.new(
            self.secret.encode(),
            payload_json.encode(),
            hashlib.sha256,
        ).digest()
        return sig_bytes.hex()

    def _send_request(
        self,
        payload_json: str,
        signature: str,
        digest: str,
    ) -> str:
        """Send the HTTP(S) request and return the response body.

        Enforces timeout and response cap via select(2) on the socket.
        Raises on timeout, response cap exceeded, or any network error.
        """
        # Validate scheme
        if not (self.endpoint.startswith("https://") or (self.test_mode and self.endpoint.startswith("http://"))):
            raise PosterError(
                f"Endpoint must be HTTPS (or HTTP in test_mode): {self.endpoint}"
            )

        # Build request headers
        req = urllib.request.Request(
            self.endpoint,
            data=payload_json.encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Signature": signature,
                "X-Digest": digest,
            },
        )

        # Send with timeout and response cap
        deadline = time.monotonic() + self.timeout_seconds
        return self._read_bounded_response(req, deadline)

    def _read_bounded_response(
        self,
        req: urllib.request.Request,
        deadline: float,
    ) -> str:
        """Open the request and read response with timeout and cap enforcement.

        Returns response body as string.
        Raises PosterError on timeout, cap exceeded, or HTTP error.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PosterError(f"Timeout before sending request (deadline already passed)")

        try:
            # Open with socket-level timeout
            with urllib.request.urlopen(
                req,
                timeout=remaining,
            ) as response:
                # Read response in bounded chunks
                response_body = self._read_bounded_body(response, deadline)
                return response_body.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            # Server returned 4xx/5xx
            raise PosterError(f"HTTP {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            raise PosterError(f"URL error: {exc.reason}")

    def _read_bounded_body(
        self,
        response: urllib.request.Response,
        deadline: float,
    ) -> bytes:
        """Read response body with cap and deadline enforcement."""
        body_parts: list[bytes] = []
        combined_bytes = 0
        chunk_size = 65536

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PosterError("Timeout reading response body")

            # Use socket-level timeout for the read
            try:
                chunk = response.read(chunk_size)
            except OSError as exc:
                raise PosterError(f"Read error: {exc}")

            if not chunk:
                break

            combined_bytes += len(chunk)
            if combined_bytes > self.response_cap_bytes:
                raise PosterError(
                    f"Response body exceeded cap of {self.response_cap_bytes} bytes"
                )

            body_parts.append(chunk)

        return b"".join(body_parts)
