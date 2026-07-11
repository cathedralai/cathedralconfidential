"""Miner HTTP worker: /v1/evidence and /v1/sat-work (stdlib only).

A lightweight HTTP/1.1 server a miner process runs locally. The validator
(or RemoteMiner proxy) calls these endpoints to collect attestation evidence
and SAT solutions.

Security surface
----------------
- Global semaphore: at most ``max_concurrent`` requests processed at once;
  extras receive 503 immediately (DoS budget control).
- Request body cap (``max_body`` bytes); oversized → 413.
- Strict JSON schemas: unknown or missing keys → 400.
- Optional bearer token: missing/wrong ``Authorization`` header → 401.
- Output is naturally bounded: responses are deterministic small JSON.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cathedral.attest import collect_tdx
from cathedral.common import Evidence
from cathedral.lanes.sat import _compute_challenge_id, solve_sat
from cathedral.lanes.sat_types import SatInstance

MAX_REQUEST_BODY: int = 64 * 1024  # 64 KiB
MAX_CONCURRENT: int = 1

# Exact allowed key sets for strict schema validation.
_EVIDENCE_REQUEST_KEYS: frozenset[str] = frozenset({"nonce_hex", "assigned_hotkey"})
_SAT_REQUEST_KEYS: frozenset[str] = frozenset({"challenge_id", "assigned_hotkey", "instance", "seed"})
_INSTANCE_KEYS: frozenset[str] = frozenset({"n_vars", "clauses"})


def _make_handler(
    semaphore: threading.Semaphore,
    bearer_token: str | None,
    evidence_collector: Callable[[bytes, str], Evidence],
    max_body: int,
) -> type:
    """Return a BaseHTTPRequestHandler subclass closed over shared server state."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:  # silence stdout noise
            pass

        # ------------------------------------------------------------------
        # HTTP plumbing
        # ------------------------------------------------------------------

        def _send_json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _check_auth(self) -> bool:
            if bearer_token is None:
                return True
            auth = self.headers.get("Authorization", "")
            return auth == f"Bearer {bearer_token}"

        def _read_body(self) -> bytes | None:
            """Read request body up to ``max_body`` bytes; None → oversized."""
            length_str = self.headers.get("Content-Length")
            if length_str is None:
                return b""
            try:
                length = int(length_str)
            except ValueError:
                return None
            if length > max_body:
                return None
            return self.rfile.read(length)

        # ------------------------------------------------------------------
        # Dispatch
        # ------------------------------------------------------------------

        def do_POST(self) -> None:
            if not self._check_auth():
                self._send_json(401, {"error": "unauthorized"})
                return

            if not semaphore.acquire(blocking=False):
                self._send_json(503, {"error": "busy"})
                return

            try:
                self._handle_post()
            finally:
                semaphore.release()

        def _handle_post(self) -> None:
            raw = self._read_body()
            if raw is None:
                self._send_json(413, {"error": "request too large"})
                return

            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid JSON"})
                return

            if not isinstance(body, dict):
                self._send_json(400, {"error": "expected JSON object"})
                return

            path = self.path.split("?")[0]
            if path == "/v1/evidence":
                self._handle_evidence(body)
            elif path == "/v1/sat-work":
                self._handle_sat_work(body)
            else:
                self._send_json(404, {"error": "not found"})

        # ------------------------------------------------------------------
        # /v1/evidence
        # ------------------------------------------------------------------

        def _handle_evidence(self, body: dict) -> None:
            got_keys = set(body.keys())
            if got_keys != _EVIDENCE_REQUEST_KEYS:
                extra = sorted(got_keys - _EVIDENCE_REQUEST_KEYS)
                missing = sorted(_EVIDENCE_REQUEST_KEYS - got_keys)
                self._send_json(400, {
                    "error": "schema violation",
                    "extra_keys": extra,
                    "missing_keys": missing,
                })
                return

            nonce_hex = body["nonce_hex"]
            hotkey = body["assigned_hotkey"]

            if not isinstance(nonce_hex, str):
                self._send_json(400, {"error": "nonce_hex must be a string"})
                return
            if not isinstance(hotkey, str) or not hotkey:
                self._send_json(400, {"error": "assigned_hotkey must be a non-empty string"})
                return

            try:
                nonce = bytes.fromhex(nonce_hex)
            except ValueError:
                self._send_json(400, {"error": "nonce_hex: invalid hex"})
                return

            try:
                evidence: Evidence = evidence_collector(nonce, hotkey)
            except Exception as exc:
                self._send_json(500, {"error": f"evidence collection failed: {exc}"})
                return

            self._send_json(200, {
                "kind": evidence.kind.value,
                "quote_hex": evidence.quote.hex(),
                "nonce_hex": evidence.nonce.hex(),
                "miner_hotkey": evidence.miner_hotkey,
                "cert_chain_hex": [b.hex() for b in evidence.cert_chain],
            })

        # ------------------------------------------------------------------
        # /v1/sat-work
        # ------------------------------------------------------------------

        def _handle_sat_work(self, body: dict) -> None:
            got_keys = set(body.keys())
            if got_keys != _SAT_REQUEST_KEYS:
                extra = sorted(got_keys - _SAT_REQUEST_KEYS)
                missing = sorted(_SAT_REQUEST_KEYS - got_keys)
                self._send_json(400, {
                    "error": "schema violation",
                    "extra_keys": extra,
                    "missing_keys": missing,
                })
                return

            challenge_id = body["challenge_id"]
            hotkey = body["assigned_hotkey"]
            instance_raw = body["instance"]
            seed = body["seed"]

            if not isinstance(challenge_id, str) or not challenge_id:
                self._send_json(400, {"error": "challenge_id must be a non-empty string"})
                return
            if not isinstance(hotkey, str) or not hotkey:
                self._send_json(400, {"error": "assigned_hotkey must be a non-empty string"})
                return
            if not isinstance(seed, int) or isinstance(seed, bool):
                self._send_json(400, {"error": "seed must be an integer"})
                return
            if not isinstance(instance_raw, dict):
                self._send_json(400, {"error": "instance must be a JSON object"})
                return

            got_inst_keys = set(instance_raw.keys())
            if got_inst_keys != _INSTANCE_KEYS:
                extra = sorted(got_inst_keys - _INSTANCE_KEYS)
                missing = sorted(_INSTANCE_KEYS - got_inst_keys)
                self._send_json(400, {
                    "error": "instance: schema violation",
                    "extra_keys": extra,
                    "missing_keys": missing,
                })
                return

            try:
                n_vars = instance_raw["n_vars"]
                clauses = instance_raw["clauses"]
                if not isinstance(n_vars, int) or isinstance(n_vars, bool):
                    raise ValueError("n_vars must be integer")
                if not isinstance(clauses, list):
                    raise ValueError("clauses must be list")
                for clause in clauses:
                    if not isinstance(clause, list):
                        raise ValueError("each clause must be a list")
                    for lit in clause:
                        if not isinstance(lit, int) or isinstance(lit, bool):
                            raise ValueError("literals must be integers")
            except (ValueError, TypeError) as exc:
                self._send_json(400, {"error": f"instance: {exc}"})
                return

            inst = SatInstance(n_vars=n_vars, clauses=clauses)

            # Verify challenge_id is consistent with the instance + seed the
            # caller claims to have dispatched — prevents mismatched submissions.
            computed_id = _compute_challenge_id(inst, seed)
            if computed_id != challenge_id:
                self._send_json(400, {"error": "challenge_id mismatch"})
                return

            assignment = solve_sat(inst)
            work_units = float(len(clauses))

            self._send_json(200, {
                "satisfiable": assignment is not None,
                "assignment": assignment,
                "work_units": work_units,
                "challenge_id": challenge_id,
                "miner_hotkey": hotkey,
            })

    return _Handler


class WorkerServer:
    """Stdlib HTTP server exposing /v1/evidence and /v1/sat-work.

    Parameters
    ----------
    host, port:
        Bind address. Use ``port=0`` for OS-assigned (useful in tests).
    bearer_token:
        If set, all requests must supply ``Authorization: Bearer <token>``;
        missing or wrong token → 401.
    evidence_collector:
        ``Callable(nonce: bytes, hotkey: str) -> Evidence``.
        Defaults to :func:`cathedral.attest.collect_tdx`.
    max_body:
        Maximum request body bytes (default 64 KiB). Oversized → 413.
    max_concurrent:
        Semaphore width (default 1). Extra simultaneous requests → 503.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        bearer_token: str | None = None,
        evidence_collector: Callable[[bytes, str], Evidence] | None = None,
        max_body: int = MAX_REQUEST_BODY,
        max_concurrent: int = MAX_CONCURRENT,
    ) -> None:
        self._semaphore = threading.Semaphore(max_concurrent)
        collector = evidence_collector if evidence_collector is not None else collect_tdx
        handler_cls = _make_handler(self._semaphore, bearer_token, collector, max_body)
        self._server = ThreadingHTTPServer((host, port), handler_cls)

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

    def __enter__(self) -> "WorkerServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()
