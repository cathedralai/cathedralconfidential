"""Bounded worker for evidence collection and canonical SAT work.

``WorkerServer`` listens on loopback behind an HTTPS terminator unless an
explicit development-only override is supplied; tests may also install a TLS
context directly. Production v2 evidence is accepted only for the configured
in-guest channel-key digest. The corresponding client requires HTTPS by
default.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import math
import multiprocessing
import re
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cathedral.attest import collect_tdx
from cathedral.cc_gpu import CcGpuCapability
from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    MAX_COMPOSITE_JWT_BYTES,
    MAX_EVIDENCE_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_COMPONENTS,
    MAX_EVIDENCE_QUOTE_BYTES,
    MAX_EVIDENCE_RESPONSE_BODY,
)
from cathedral.lanes.sat import (
    MAX_SEED,
    MIN_SEED,
    _canonical_instance,
    _compute_challenge_id,
    solve_sat,
    validate_sat_instance,
)
from cathedral.lanes.sat_types import SatInstance

MAX_REQUEST_BODY: int = 64 * 1024
MAX_RESPONSE_BODY: int = MAX_EVIDENCE_RESPONSE_BODY
MAX_CONCURRENT: int = 1
MAX_HOTKEY_LENGTH: int = 256
MAX_BEARER_TOKEN_LENGTH: int = 4096
MAX_CUSTOMER_SAT_SOLVE_SECONDS: float = 30.0
MAX_CUSTOMER_SAT_MEMORY_BYTES: int = 256 * 1024 * 1024

_EVIDENCE_REQUEST_KEYS = frozenset({"nonce_hex", "assigned_hotkey"})
_EVIDENCE_V2_REQUEST_KEYS = _EVIDENCE_REQUEST_KEYS | frozenset(
    {"report_data_version", "channel_binding_type", "channel_binding_digest_hex"}
)
_SAT_REQUEST_KEYS = frozenset({"challenge_id", "assigned_hotkey", "instance", "seed"})
_CAPABILITIES_REQUEST_KEYS: frozenset[str] = frozenset()
_INSTANCE_KEYS = frozenset({"n_vars", "clauses"})
_DECIMAL_RE = re.compile(r"[0-9]+")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _customer_sat_solve_child(connection, instance: SatInstance, cpu_seconds: int) -> None:
    """Solve one untrusted instance inside a resource-capped child process."""

    try:
        if sys.platform.startswith("linux"):
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            resource.setrlimit(
                resource.RLIMIT_AS,
                (MAX_CUSTOMER_SAT_MEMORY_BYTES, MAX_CUSTOMER_SAT_MEMORY_BYTES),
            )
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        connection.send(("ok", solve_sat(instance)))
    except BaseException:
        try:
            connection.send(("error", None))
        except BaseException:
            pass
    finally:
        connection.close()


def _solve_customer_sat_bounded(
    instance: SatInstance,
    timeout_seconds: float,
) -> tuple[bool, list[int] | None]:
    """Return ``(completed, assignment)`` and kill work that exceeds its budget."""

    budget = min(float(timeout_seconds), MAX_CUSTOMER_SAT_SOLVE_SECONDS)
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_customer_sat_solve_child,
        args=(child, instance, max(1, math.ceil(budget))),
        daemon=True,
    )
    started = False
    try:
        process.start()
        started = True
        child.close()
        process.join(budget)
        if process.is_alive():
            process.terminate()
            process.join(1.0)
        if process.is_alive():
            process.kill()
            process.join(1.0)
        if process.exitcode != 0 or not parent.poll():
            return False, None
        status, assignment = parent.recv()
        if status != "ok" or (
            assignment is not None
            and (
                not isinstance(assignment, list)
                or len(assignment) != instance.n_vars
                or any(isinstance(item, bool) or not isinstance(item, int) for item in assignment)
            )
        ):
            return False, None
        return True, assignment
    except (OSError, EOFError, RuntimeError):
        return False, None
    finally:
        try:
            child.close()
        except OSError:
            pass
        try:
            parent.close()
        except OSError:
            pass
        if started and process.is_alive():
            process.kill()
            process.join(1.0)


def _evidence_fits_transport(evidence: Evidence) -> bool:
    jwt = evidence.composite_jwt
    return (
        isinstance(evidence.quote, bytes)
        and 0 < len(evidence.quote) <= MAX_EVIDENCE_QUOTE_BYTES
        and isinstance(evidence.cert_chain, list)
        and len(evidence.cert_chain) <= MAX_EVIDENCE_CERTIFICATES
        and all(
            isinstance(certificate, bytes)
            and 0 < len(certificate) <= MAX_EVIDENCE_CERTIFICATE_BYTES
            for certificate in evidence.cert_chain
        )
        and (
            jwt is None
            or (
                isinstance(jwt, str)
                and bool(jwt)
                and jwt.isascii()
                and len(jwt) <= MAX_COMPOSITE_JWT_BYTES
                and all(ord(character) >= 0x20 for character in jwt)
            )
        )
    )


def _make_handler(
    semaphore: threading.Semaphore,
    configured_hotkey: str,
    bearer_token: str | None,
    evidence_collector: Callable[..., Evidence | tuple[Evidence, ...] | list[Evidence]],
    configured_channel_binding: ChannelBinding | None,
    max_body: int,
    max_response_body: int,
    request_timeout: float,
    allow_noncanonical_sat: bool,
    cc_gpu_capability_provider: Callable[[], CcGpuCapability],
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
            if bearer_token is None:
                return True
            return hmac.compare_digest(
                self.headers.get("Authorization", ""), f"Bearer {bearer_token}"
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
            path = self.path.partition("?")[0]
            # Fresh evidence is deliberately credential-free.  The worker's
            # concurrency and body limits protect this public challenge path;
            # bearer credentials are sent only after the validator has
            # verified the attested channel and are required for work.
            if path != "/v1/evidence" and not self._check_auth():
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
            elif path == "/v1/capabilities":
                if set(body) != _CAPABILITIES_REQUEST_KEYS:
                    self._send_json(400, {"error": "invalid capabilities schema"})
                else:
                    try:
                        cc_gpu_capability = cc_gpu_capability_provider()
                    except Exception:
                        cc_gpu_capability = CcGpuCapability()
                    if not isinstance(cc_gpu_capability, CcGpuCapability):
                        cc_gpu_capability = CcGpuCapability()
                    self._send_json(
                        200,
                        {
                            "customer_sat": allow_noncanonical_sat,
                            "cc_gpu": dict(cc_gpu_capability.document()),
                        },
                    )
            elif path == "/v1/sat-work":
                self._handle_sat_work(body)
            else:
                self._send_json(404, {"error": "not found"})

        def _handle_evidence(self, body: dict[str, object]) -> None:
            keys = frozenset(body)
            if keys not in {_EVIDENCE_REQUEST_KEYS, _EVIDENCE_V2_REQUEST_KEYS}:
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

            report_data_version = body.get("report_data_version", 1)
            if isinstance(report_data_version, bool) or not isinstance(
                report_data_version, int
            ):
                self._send_json(400, {"error": "invalid report data version"})
                return
            requested_binding: ChannelBinding | None = None
            if report_data_version == 2:
                try:
                    binding_type = ChannelBindingType(body["channel_binding_type"])
                    digest_hex = body["channel_binding_digest_hex"]
                    if (
                        not isinstance(digest_hex, str)
                        or _SHA256_RE.fullmatch(digest_hex) is None
                    ):
                        raise ValueError
                    requested_binding = ChannelBinding(
                        binding_type, bytes.fromhex(digest_hex)
                    )
                except (KeyError, TypeError, ValueError):
                    self._send_json(400, {"error": "invalid channel binding"})
                    return
                if configured_channel_binding is None:
                    self._send_json(503, {"error": "channel binding unavailable"})
                    return
                if requested_binding != configured_channel_binding:
                    self._send_json(403, {"error": "channel binding mismatch"})
                    return
            elif report_data_version != 1:
                self._send_json(400, {"error": "unsupported report data version"})
                return

            try:
                if report_data_version == 2:
                    collected = evidence_collector(
                        nonce,
                        configured_hotkey,
                        channel_binding=configured_channel_binding,
                        report_data_version=2,
                    )
                else:
                    collected = evidence_collector(nonce, configured_hotkey)
            except Exception:
                self._send_json(500, {"error": "evidence collection failed"})
                return
            if isinstance(collected, Evidence):
                evidences = (collected,)
            elif isinstance(collected, (tuple, list)) and all(
                isinstance(item, Evidence) for item in collected
            ):
                evidences = tuple(collected)
            else:
                self._send_json(500, {"error": "evidence collection failed"})
                return
            if (
                not 1 <= len(evidences) <= MAX_EVIDENCE_COMPONENTS
                or any(
                    evidence.nonce != nonce
                    or evidence.miner_hotkey != configured_hotkey
                    or not _evidence_fits_transport(evidence)
                    for evidence in evidences
                )
                or (
                    len(evidences) == 2
                    and {evidence.kind for evidence in evidences}
                    != {EvidenceKind.TDX, EvidenceKind.GPU_CC}
                )
            ):
                self._send_json(500, {"error": "evidence collection failed"})
                return

            response_items: list[dict[str, object]] = []
            for evidence in evidences:
                item: dict[str, object] = {
                    "kind": evidence.kind.value,
                    "quote_hex": evidence.quote.hex(),
                    "nonce_hex": nonce.hex(),
                    "assigned_hotkey": configured_hotkey,
                    "cert_chain_hex": [cert.hex() for cert in evidence.cert_chain],
                }
                response_items.append(item)
            if report_data_version == 2:
                if any(
                    evidence.report_data_version != 2
                    or evidence.channel_binding != configured_channel_binding
                    for evidence in evidences
                ):
                    self._send_json(500, {"error": "evidence collection failed"})
                    return
                assert configured_channel_binding is not None
                for evidence, item in zip(evidences, response_items, strict=True):
                    item.update({
                        "report_data_version": 2,
                        "channel_binding_type": configured_channel_binding.binding_type.value,
                        "channel_binding_digest_hex": configured_channel_binding.digest.hex(),
                    })
                    if len(evidences) > 1:
                        item["composite_jwt"] = evidence.composite_jwt
            if len(response_items) == 1:
                self._send_json(200, response_items[0])
            else:
                self._send_json(200, {"evidence": response_items})

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
            canonical = instance == _canonical_instance(seed)
            if not allow_noncanonical_sat and not canonical:
                self._send_json(400, {"error": "noncanonical SAT instance"})
                return
            if _compute_challenge_id(instance, seed) != challenge_id:
                self._send_json(400, {"error": "challenge_id mismatch"})
                return

            if canonical:
                assignment = solve_sat(instance)
            else:
                completed, assignment = _solve_customer_sat_bounded(
                    instance,
                    request_timeout,
                )
                if not completed:
                    self._send_json(503, {"error": "customer SAT solve exceeded resource limits"})
                    return
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
    instance = SatInstance(n_vars=n_vars, clauses=clauses)
    try:
        validate_sat_instance(instance)
    except ValueError:
        return None
    return instance


class WorkerServer:
    """Expose one miner identity over bounded plain HTTP.

    Production deployments must keep this server on loopback behind an HTTPS terminator.
    SAT work is restricted to deterministic ``SatLane`` canonical backfill by
    default. Customer-submitted SAT is an explicit authenticated deployment mode.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        configured_hotkey: str,
        bearer_token: str | None = None,
        evidence_collector: Callable[
            ..., Evidence | tuple[Evidence, ...] | list[Evidence]
        ]
        | None = None,
        channel_binding: ChannelBinding | None = None,
        tls_context: ssl.SSLContext | None = None,
        max_body: int = MAX_REQUEST_BODY,
        max_concurrent: int = MAX_CONCURRENT,
        max_response_body: int = MAX_RESPONSE_BODY,
        timeout: float = 10.0,
        allow_noncanonical_sat: bool = False,
        cc_gpu_capability_provider: Callable[[], CcGpuCapability] | None = None,
        allow_non_loopback_for_development: bool = False,
    ) -> None:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not isinstance(allow_non_loopback_for_development, bool):
            raise ValueError("allow_non_loopback_for_development must be a boolean")
        if not loopback and not allow_non_loopback_for_development:
            raise ValueError("plain worker HTTP must bind a loopback address")
        if (
            not isinstance(configured_hotkey, str)
            or not configured_hotkey
            or len(configured_hotkey) > MAX_HOTKEY_LENGTH
        ):
            raise ValueError("configured_hotkey must be a non-empty bounded string")
        if bearer_token is not None and (
            not isinstance(bearer_token, str)
            or not bearer_token
            or len(bearer_token) > MAX_BEARER_TOKEN_LENGTH
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in bearer_token)
        ):
            raise ValueError("bearer_token must be a nonempty bounded ASCII string")
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
        if not isinstance(allow_noncanonical_sat, bool):
            raise ValueError("allow_noncanonical_sat must be a boolean")
        if cc_gpu_capability_provider is not None and not callable(
            cc_gpu_capability_provider
        ):
            raise ValueError("cc_gpu_capability_provider must be callable")
        if channel_binding is not None and not isinstance(
            channel_binding, ChannelBinding
        ):
            raise ValueError("channel_binding must be a ChannelBinding")
        if allow_noncanonical_sat and (bearer_token is None or channel_binding is None):
            raise ValueError(
                "customer SAT requires bearer authentication and a configured channel binding"
            )
        if allow_noncanonical_sat and allow_non_loopback_for_development:
            raise ValueError("customer SAT cannot use the development non-loopback HTTP bind")
        if tls_context is not None and not isinstance(tls_context, ssl.SSLContext):
            raise ValueError("tls_context must be an SSLContext")
        if tls_context is not None and channel_binding is None:
            raise ValueError("TLS worker requires its configured channel binding")

        semaphore = threading.Semaphore(max_concurrent)
        handler = _make_handler(
            semaphore,
            configured_hotkey,
            bearer_token,
            evidence_collector or collect_tdx,
            channel_binding,
            max_body,
            max_response_body,
            float(timeout),
            allow_noncanonical_sat,
            cc_gpu_capability_provider or CcGpuCapability,
        )
        self._server = ThreadingHTTPServer((host, port), handler)
        self._tls_enabled = tls_context is not None
        if tls_context is not None:
            self._server.socket = tls_context.wrap_socket(
                self._server.socket, server_side=True
            )

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def base_url(self) -> str:
        scheme = "https" if self._tls_enabled else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "WorkerServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()
