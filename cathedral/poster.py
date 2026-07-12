"""Exact-body publisher for Cathedral external score snapshots."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class PosterError(Exception):
    """Raised when an external-score publication is unsafe or unsuccessful."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class Poster:
    """POST already-persisted report bytes without reserializing or mutating them."""

    ROUTE = "/v1/external-scores/violet"

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        secret: str | bytes,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        total_timeout: float = 30.0,
        response_cap_bytes: int = 1024 * 1024,
        allow_http_for_tests: bool = False,
        test_mode: bool | None = None,
    ) -> None:
        if test_mode is not None:
            allow_http_for_tests = test_mode
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" and not (allow_http_for_tests and parsed.scheme == "http"):
            raise PosterError("endpoint must use HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PosterError("endpoint must not contain credentials, query, or fragment")
        if parsed.path.rstrip("/") != self.ROUTE:
            raise PosterError(f"endpoint path must be {self.ROUTE}")
        if not parsed.hostname:
            raise PosterError("endpoint must include a host")
        if not bearer_token:
            raise PosterError("bearer token is required")
        if connect_timeout <= 0 or read_timeout <= 0 or total_timeout <= 0:
            raise PosterError("timeouts must be positive")
        if response_cap_bytes <= 0:
            raise PosterError("response_cap_bytes must be positive")
        self.endpoint = endpoint
        self.bearer_token = bearer_token
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.response_cap_bytes = response_cap_bytes
        self._opener = urllib.request.build_opener(_NoRedirect())

    def post(self, report_body: bytes) -> dict[str, Any]:
        if not isinstance(report_body, bytes):
            raise PosterError("report_body must be the exact persisted bytes")
        signature = hmac.new(self.secret, report_body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            self.endpoint,
            data=report_body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
                "X-Cathedral-External-Signature": signature,
            },
        )
        deadline = time.monotonic() + self.total_timeout
        try:
            response = self._opener.open(
                request,
                timeout=min(self.connect_timeout, self._remaining(deadline)),
            )
            with response:
                status = response.getcode()
                if status < 200 or status >= 300:
                    raise PosterError(f"unexpected HTTP status {status}")
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        if int(length) > self.response_cap_bytes:
                            raise PosterError("response body exceeds configured cap")
                    except ValueError as exc:
                        raise PosterError("invalid Content-Length response header") from exc
                body = self._read_response(response, deadline)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise PosterError(f"redirect refused (HTTP {exc.code})") from exc
            raise PosterError(f"HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise PosterError(f"request failed or timed out: {exc}") from exc
        except OSError as exc:
            raise PosterError(f"request failed: {exc}") from exc

        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PosterError("response must be valid UTF-8 JSON") from exc
        if not isinstance(decoded, dict):
            raise PosterError("response JSON must be an object")
        return decoded

    def _read_response(self, response: Any, deadline: float) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            remaining = self._remaining(deadline)
            self._set_socket_timeout(response, min(self.read_timeout, remaining))
            chunk = response.read(min(64 * 1024, self.response_cap_bytes - size + 1))
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > self.response_cap_bytes:
                raise PosterError("response body exceeds configured cap")
            chunks.append(chunk)

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PosterError("total request deadline exceeded")
        return remaining

    @staticmethod
    def _set_socket_timeout(response: Any, timeout: float) -> None:
        candidates = (
            getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None),
            getattr(getattr(response, "fp", None), "_sock", None),
        )
        for candidate in candidates:
            if candidate is not None:
                candidate.settimeout(timeout)
                return
