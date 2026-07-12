"""Bounded stdlib HTTP server for evidence collection and SAT work."""
from __future__ import annotations

import json
import math
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cathedral.attest import collect_tdx
from cathedral.common import Evidence
from cathedral.lanes.sat import _compute_challenge_id, solve_sat
from cathedral.lanes.sat_types import SatInstance

MAX_REQUEST_BODY: int = 64 * 1024
MAX_RESPONSE_BODY: int = 64 * 1024
MAX_CONCURRENT: int = 1
MAX_HOTKEY_LENGTH: int = 256
MAX_N_VARS: int = 4096
MAX_CLAUSES: int = 8192
MAX_LITERALS: int = 65_536
MAX_LITERALS_PER_CLAUSE: int = 1024
MIN_SEED: int = -(2**63)
MAX_SEED: int = 2**63 - 1

_EVIDENCE_REQUEST_KEYS = frozenset({"nonce_hex", "assigned_hotkey"})
_SAT_REQUEST_KEYS = frozenset({"challenge_id", "assigned_hotkey", "instance", "seed"})
_INSTANCE_KEYS = frozenset({"n_vars", "clauses"})
_DECIMAL_RE = re.compile(r"[0-9]+")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _make_handler(
    semaphore: threading.Semaphore,
    configured_hotkey: str,
    bearer_token: str | None,
    evidence_collector: Callable[[bytes, str], Evidence],
    max_body: int,
    max_response_body: int,
    request_timeout: float,
) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(request_timeout)

        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def _send_json(self, code: int, obj: dict[str, object]) -> None:
            body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            if len(body) > max_response_body:
                code = 500
                body = b'{"error":"response too large"}'
                if len(body) > max_response_body:
                    body = b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _check_auth(self) -> bool:
            return bearer_token is None or self.headers.get("Authorization", "") == (
                f"Bearer {bearer_token}"
            )

        def _read_body(self) -> tuple[bytes | None, int, str]:
            if self.headers.get("Transfer-Encoding") is not None:
                return None, 400, "invalid request framing"
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                return None, 411, "content length required"
            length_text = lengths[0]
            if _DECIMAL_RE.fullmatch(length_text) is None:
                return None, 400, "invalid content length"
            length = int(length_text)
            if length > max_body:
                return None, 413, "request too large"
            try:
                body = self.rfile.read(length)
            except (socket.timeout, TimeoutError, OSError):
                return None, 400, "incomplete request body"
            if len(body) != length:
                return None, 400, "incomplete request body"
            return body, 200, ""

        def do_POST(self) -> None:
            if not self._check_auth():
                self._send_json(401, {"error": "unauthorized"})
                return
            if not semaphore.acquire(blocking=False):
                self._send_json(503, {"error": "busy"})
                return
            try:
                self._handle_post()
            except (socket.timeout, TimeoutError, OSError):
                try:
                    self._send_json(400, {"error": "request failed"})
                except OSError:
                    pass
            except Exception:
                try:
                    self._send_json(500, {"error": "internal error"})
                except OSError:
                    pass
            finally:
                semaphore.release()

        def _handle_post(self) -> None:
            raw, error_code, error_message = self._read_body()
            if raw is None:
                self._send_json(error_code, {"error": error_message})
                return
            try:
                body = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            if not isinstance(body, dict):
                self._send_json(400, {"error": "expected JSON object"})
                return

            path = self.path.partition("?")[0]
            if path == "/v1/evidence":
                self._handle_evidence(body)
            elif path == "/v1/sat-work":
                self._handle_sat_work(body)
            else:
                self._send_json(404, {"error": "not found"})

        def _handle_evidence(self, body: dict[str, object]) -> None:
            if set(body) != _EVIDENCE_REQUEST_KEYS:
                self._send_json(400, {"error": "invalid evidence schema"})
                return
            nonce_hex = body["nonce_hex"]
            hotkey = body["assigned_hotkey"]
            if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_LENGTH:
                self._send_json(400, {"error": "invalid assigned_hotkey"})
                return
            if hotkey != configured_hotkey:
                self._send_json(403, {"error": "assigned_hotkey mismatch"})
                return
            if not isinstance(nonce_hex, str) or _SHA256_RE.fullmatch(nonce_hex) is None:
                self._send_json(400, {"error": "nonce must be exactly 32 bytes of hex"})
                return
            nonce = bytes.fromhex(nonce_hex)

            try:
                evidence = evidence_collector(nonce, configured_hotkey)
            except Exception:
                self._send_json(500, {"error": "evidence collection failed"})
                return
            if evidence.nonce != nonce or evidence.miner_hotkey != configured_hotkey:
                self._send_json(500, {"error": "evidence collection failed"})
                return

            self._send_json(
                200,
                {
                    "kind": evidence.kind.value,
                    "quote_hex": evidence.quote.hex(),
                    "nonce_hex": nonce.hex(),
                    "assigned_hotkey": configured_hotkey,
                    "cert_chain_hex": [cert.hex() for cert in evidence.cert_chain],
                },
            )

        def _handle_sat_work(self, body: dict[str, object]) -> None:
            if set(body) != _SAT_REQUEST_KEYS:
                self._send_json(400, {"error": "invalid SAT schema"})
                return
            challenge_id = body["challenge_id"]
            hotkey = body["assigned_hotkey"]
            instance_raw = body["instance"]
            seed = body["seed"]

            if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_LENGTH:
                self._send_json(400, {"error": "invalid assigned_hotkey"})
                return
            if hotkey != configured_hotkey:
                self._send_json(403, {"error": "assigned_hotkey mismatch"})
                return
            if not isinstance(challenge_id, str) or _SHA256_RE.fullmatch(challenge_id) is None:
                self._send_json(400, {"error": "invalid challenge_id"})
                return
            if (
                isinstance(seed, bool)
                or not isinstance(seed, int)
                or not MIN_SEED <= seed <= MAX_SEED
            ):
                self._send_json(400, {"error": "invalid seed"})
                return
            instance = _parse_instance(instance_raw)
            if instance is None:
                self._send_json(400, {"error": "invalid instance"})
                return
            if _compute_challenge_id(instance, seed) != challenge_id:
                self._send_json(400, {"error": "challenge_id mismatch"})
                return

            assignment = solve_sat(instance)
            self._send_json(
                200,
                {
                    "satisfiable": assignment is not None,
                    "assignment": assignment,
                    "work_units": float(len(instance.clauses)),
                    "challenge_id": challenge_id,
                    "assigned_hotkey": configured_hotkey,
                },
            )

    return _Handler


def _parse_instance(raw: object) -> SatInstance | None:
    if not isinstance(raw, dict) or set(raw) != _INSTANCE_KEYS:
        return None
    n_vars = raw["n_vars"]
    clauses = raw["clauses"]
    if (
        isinstance(n_vars, bool)
        or not isinstance(n_vars, int)
        or not 1 <= n_vars <= MAX_N_VARS
        or not isinstance(clauses, list)
        or len(clauses) > MAX_CLAUSES
    ):
        return None

    literal_count = 0
    for clause in clauses:
        if not isinstance(clause, list) or len(clause) > MAX_LITERALS_PER_CLAUSE:
            return None
        literal_count += len(clause)
        if literal_count > MAX_LITERALS:
            return None
        for literal in clause:
            if (
                isinstance(literal, bool)
                or not isinstance(literal, int)
                or literal == 0
                or abs(literal) > n_vars
            ):
                return None
    return SatInstance(n_vars=n_vars, clauses=clauses)


class WorkerServer:
    """Expose one configured miner identity over bounded HTTP endpoints."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        configured_hotkey: str,
        bearer_token: str | None = None,
        evidence_collector: Callable[[bytes, str], Evidence] | None = None,
        max_body: int = MAX_REQUEST_BODY,
        max_concurrent: int = MAX_CONCURRENT,
        max_response_body: int = MAX_RESPONSE_BODY,
        timeout: float = 10.0,
    ) -> None:
        if (
            not isinstance(configured_hotkey, str)
            or not configured_hotkey
            or len(configured_hotkey) > MAX_HOTKEY_LENGTH
        ):
            raise ValueError("configured_hotkey must be a non-empty bounded string")
        for name, value in (
            ("max_body", max_body),
            ("max_concurrent", max_concurrent),
            ("max_response_body", max_response_body),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")

        semaphore = threading.Semaphore(max_concurrent)
        handler = _make_handler(
            semaphore,
            configured_hotkey,
            bearer_token,
            evidence_collector or collect_tdx,
            max_body,
            max_response_body,
            float(timeout),
        )
        self._server = ThreadingHTTPServer((host, port), handler)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "WorkerServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()
