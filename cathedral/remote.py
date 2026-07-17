"""Typed, bounded HTTPS-by-default client for a Cathedral miner worker."""
from __future__ import annotations

import http.client
import json
import math
import socket
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from cathedral.channel import ChannelBindingError, tls_spki_binding
from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    MAX_COMPOSITE_JWT_BYTES,
    MAX_CPU_EVIDENCE_RESPONSE_BODY,
    MAX_EVIDENCE_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_QUOTE_BYTES,
)
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

MAX_RESPONSE_BODY: int = MAX_CPU_EVIDENCE_RESPONSE_BODY
MAX_SAT_RESPONSE_BODY: int = 64 * 1024
MAX_HOTKEY_LENGTH: int = 256
MAX_N_VARS: int = 4096
MAX_CLAUSES: int = 8192
MAX_LITERALS: int = 65_536
MAX_LITERALS_PER_CLAUSE: int = 1024
MIN_SEED: int = -(2**63)
MAX_SEED: int = 2**63 - 1

_EVIDENCE_RESPONSE_KEYS = frozenset(
    {"kind", "quote_hex", "nonce_hex", "assigned_hotkey", "cert_chain_hex"}
)
_EVIDENCE_V2_RESPONSE_KEYS = _EVIDENCE_RESPONSE_KEYS | frozenset(
    {"report_data_version", "channel_binding_type", "channel_binding_digest_hex"}
)
_EVIDENCE_BUNDLE_RESPONSE_KEYS = frozenset({"evidence"})
_EVIDENCE_BUNDLE_ITEM_KEYS = _EVIDENCE_V2_RESPONSE_KEYS | frozenset(
    {"composite_jwt"}
)
_SAT_RESPONSE_KEYS = frozenset(
    {"satisfiable", "assignment", "work_units", "challenge_id", "assigned_hotkey"}
)
_HEX_DIGITS = frozenset(string.hexdigits)


class RemoteError(Exception):
    """A bounded, caller-safe failure returned by :class:`RemoteMiner`."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class RemoteMiner:
    """Proxy a single enrolled miner identity to its HTTPS worker."""

    def __init__(
        self,
        endpoint: str,
        hotkey: str,
        *,
        bearer_token: str | None = None,
        timeout: float = 10.0,
        max_response_body: int = MAX_RESPONSE_BODY,
        allow_insecure_http: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_LENGTH:
            raise ValueError("hotkey must be a non-empty bounded string")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        if (
            isinstance(max_response_body, bool)
            or not isinstance(max_response_body, int)
            or max_response_body <= 0
        ):
            raise ValueError("max_response_body must be a positive integer")
        if not isinstance(allow_insecure_http, bool):
            raise ValueError("allow_insecure_http must be a boolean")

        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_insecure_http:
            raise ValueError("endpoint must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("endpoint must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("endpoint must not contain a query or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("endpoint must not contain a path")
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise ValueError("ssl_context must be an SSLContext")
        if ssl_context is not None and (
            ssl_context.verify_mode != ssl.CERT_REQUIRED
            or not ssl_context.check_hostname
        ):
            raise ValueError("ssl_context must verify certificates and hostnames")

        self._endpoint = endpoint.rstrip("/")
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._hotkey = hotkey
        self._bearer_token = bearer_token
        self._timeout = float(timeout)
        self._max_response_body = max_response_body
        self._opener = urllib.request.build_opener(_RejectRedirects())
        self._ssl_context = ssl_context
        self._pending_binding: ChannelBinding | None = None
        self._trusted_binding: ChannelBinding | None = None

    @property
    def uid(self) -> str:
        """The enrolled hotkey, satisfying the validator's miner protocol."""
        return self._hotkey

    def collect_evidence(self, nonce: bytes) -> Evidence:
        """Collect evidence, satisfying the validator's miner protocol."""
        return self.fetch_evidence(nonce)

    def fetch_evidence(self, nonce: bytes) -> Evidence:
        evidences = self.fetch_evidence_bundle(nonce)
        if len(evidences) != 1:
            self._pending_binding = None
            raise RemoteError("single-component evidence was requested")
        return evidences[0]

    def collect_evidence_bundle(self, nonce: bytes) -> tuple[Evidence, ...]:
        """Collect a bounded evidence bundle for composite admission."""
        return self.fetch_evidence_bundle(nonce)

    def fetch_evidence_bundle(self, nonce: bytes) -> tuple[Evidence, ...]:
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise RemoteError("nonce must be exactly 32 bytes")
        self._pending_binding = None
        self._trusted_binding = None

        if self._scheme == "https":
            response, observed_binding = self._post_tls(
                "/v1/evidence",
                lambda binding: {
                    "nonce_hex": nonce.hex(),
                    "assigned_hotkey": self._hotkey,
                    "report_data_version": 2,
                    "channel_binding_type": binding.binding_type.value,
                    "channel_binding_digest_hex": binding.digest.hex(),
                },
                expected_binding=None,
                include_auth=False,
            )
        else:
            response = self._post_http(
                "/v1/evidence",
                {"nonce_hex": nonce.hex(), "assigned_hotkey": self._hotkey},
                include_auth=False,
            )
        if set(response) == _EVIDENCE_BUNDLE_RESPONSE_KEYS:
            if self._scheme != "https" or not isinstance(response["evidence"], list):
                raise RemoteError("evidence bundle has invalid schema")
            items = response["evidence"]
            if len(items) != 2 or any(not isinstance(item, dict) for item in items):
                raise RemoteError("evidence bundle has invalid component count")
            evidences = tuple(
                _evidence_from_response(
                    item,
                    nonce,
                    self._hotkey,
                    observed_binding,
                    bundle_item=True,
                )
                for item in items
            )
            if {evidence.kind for evidence in evidences} != {
                EvidenceKind.TDX,
                EvidenceKind.GPU_CC,
            }:
                raise RemoteError("evidence bundle has invalid component kinds")
            self._pending_binding = observed_binding
            return evidences

        expected = (
            _EVIDENCE_V2_RESPONSE_KEYS
            if self._scheme == "https"
            else _EVIDENCE_RESPONSE_KEYS
        )
        _check_exact_keys(response, expected, "evidence response")
        binding = observed_binding if self._scheme == "https" else None
        evidence = _evidence_from_response(
            response,
            nonce,
            self._hotkey,
            binding,
            bundle_item=False,
        )
        if binding is not None:
            self._pending_binding = binding
        return (evidence,)

    def confirm_channel_binding(self, evidence: Evidence) -> ChannelBinding:
        """Promote the live key after the caller has verified this exact quote.

        This method checks transport state; the caller owns vendor quote and
        REPORT_DATA verification and must call it only after that succeeds.
        """

        if (
            self._scheme != "https"
            or self._pending_binding is None
            or evidence.report_data_version != 2
            or evidence.channel_binding != self._pending_binding
        ):
            self._pending_binding = None
            self._trusted_binding = None
            raise RemoteError("attested channel binding mismatch")
        self._trusted_binding = self._pending_binding
        self._pending_binding = None
        return self._trusted_binding

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        _validate_work_item(item)
        payload = {
            "challenge_id": item.challenge_id,
            "assigned_hotkey": self._hotkey,
            "instance": {
                "n_vars": item.instance.n_vars,
                "clauses": item.instance.clauses,
            },
            "seed": item.seed,
        }
        if self._scheme == "https":
            if self._trusted_binding is None:
                raise RemoteError("attested channel binding is required before work")
            response, _ = self._post_tls(
                "/v1/sat-work",
                lambda _binding: payload,
                expected_binding=self._trusted_binding,
                include_auth=True,
                response_body_limit=MAX_SAT_RESPONSE_BODY,
            )
        else:
            response = self._post_http(
                "/v1/sat-work",
                payload,
                include_auth=True,
                response_body_limit=MAX_SAT_RESPONSE_BODY,
            )
        _check_exact_keys(response, _SAT_RESPONSE_KEYS, "sat-work response")

        if response["challenge_id"] != item.challenge_id:
            raise RemoteError("sat-work response challenge_id mismatch")
        if response["assigned_hotkey"] != self._hotkey:
            raise RemoteError("sat-work response hotkey mismatch")

        satisfiable = response["satisfiable"]
        assignment = response["assignment"]
        work_units = response["work_units"]
        if not isinstance(satisfiable, bool):
            raise RemoteError("sat-work response has invalid satisfiable flag")
        if (
            isinstance(work_units, bool)
            or not isinstance(work_units, (int, float))
            or not math.isfinite(work_units)
            or work_units < 0
        ):
            raise RemoteError("sat-work response has invalid work_units")
        if satisfiable:
            _validate_assignment(assignment, item.instance.n_vars)
        elif assignment is not None:
            raise RemoteError("sat-work response has invalid assignment")

        return SatCertificate(
            satisfiable=satisfiable,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
            challenge_id=item.challenge_id,
            assigned_hotkey=self._hotkey,
        )

    def _post_http(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        include_auth: bool,
        response_body_limit: int | None = None,
    ) -> dict[str, Any]:
        response_body_limit = min(
            self._max_response_body,
            self._max_response_body
            if response_body_limit is None
            else response_body_limit,
        )
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if include_auth and self._bearer_token:
            request.add_header("Authorization", f"Bearer {self._bearer_token}")

        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    if not declared.isascii() or not declared.isdecimal():
                        raise RemoteError("worker response has invalid length")
                    if int(declared) > response_body_limit:
                        raise RemoteError("worker response exceeds body limit")
                raw = response.read(response_body_limit + 1)
                if len(raw) > response_body_limit:
                    raise RemoteError("worker response exceeds body limit")
        except RemoteError:
            raise
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise RemoteError("worker redirect rejected") from None
            raise RemoteError(f"worker returned HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RemoteError("worker request timed out") from None
            raise RemoteError("worker network error") from None
        except (socket.timeout, TimeoutError):
            raise RemoteError("worker request timed out") from None
        except OSError:
            raise RemoteError("worker network error") from None
        except Exception:
            raise RemoteError("worker request failed") from None

        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RemoteError("worker response is not valid JSON") from None
        if not isinstance(decoded, dict):
            raise RemoteError("worker response must be a JSON object")
        return decoded

    def _post_tls(
        self,
        path: str,
        payload_factory: Callable[[ChannelBinding], dict[str, Any]],
        *,
        expected_binding: ChannelBinding | None,
        include_auth: bool,
        response_body_limit: int | None = None,
    ) -> tuple[dict[str, Any], ChannelBinding]:
        response_body_limit = min(
            self._max_response_body,
            self._max_response_body
            if response_body_limit is None
            else response_body_limit,
        )
        connection = http.client.HTTPSConnection(
            self._host,
            self._port,
            timeout=self._timeout,
            context=self._ssl_context,
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise RemoteError("worker TLS channel unavailable")
            certificate = connection.sock.getpeercert(binary_form=True)
            try:
                observed = tls_spki_binding(certificate)
            except ChannelBindingError:
                raise RemoteError("worker TLS certificate is invalid") from None
            if expected_binding is not None and observed != expected_binding:
                self._trusted_binding = None
                raise RemoteError("worker channel key changed")

            body = json.dumps(
                payload_factory(observed), separators=(",", ":")
            ).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if include_auth and self._bearer_token:
                headers["Authorization"] = f"Bearer {self._bearer_token}"
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise RemoteError("worker redirect rejected")
            if response.status < 200 or response.status >= 300:
                raise RemoteError(f"worker returned HTTP {response.status}")
            raw = _read_response(response, response_body_limit)
        except RemoteError:
            raise
        except (socket.timeout, TimeoutError):
            raise RemoteError("worker request timed out") from None
        except (ssl.SSLError, OSError, http.client.HTTPException):
            raise RemoteError("worker network error") from None
        except Exception:
            raise RemoteError("worker request failed") from None
        finally:
            connection.close()

        return _decode_response(raw), observed


def _read_response(response: http.client.HTTPResponse, cap: int) -> bytes:
    declared = response.getheader("Content-Length")
    if declared is not None:
        if not declared.isascii() or not declared.isdecimal():
            raise RemoteError("worker response has invalid length")
        if int(declared) > cap:
            raise RemoteError("worker response exceeds body limit")
    raw = response.read(cap + 1)
    if len(raw) > cap:
        raise RemoteError("worker response exceeds body limit")
    return raw


def _decode_response(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RemoteError("worker response is not valid JSON") from None
    if not isinstance(decoded, dict):
        raise RemoteError("worker response must be a JSON object")
    return decoded


def _response_channel_binding(response: dict[str, Any]) -> ChannelBinding:
    try:
        binding_type = ChannelBindingType(response["channel_binding_type"])
        digest_hex = response["channel_binding_digest_hex"]
        if not isinstance(digest_hex, str) or not _is_hex(digest_hex):
            raise ValueError
        digest = bytes.fromhex(digest_hex)
        return ChannelBinding(binding_type, digest)
    except (KeyError, TypeError, ValueError):
        raise RemoteError("evidence response has invalid channel binding") from None


def _evidence_from_response(
    response: dict[str, Any],
    nonce: bytes,
    hotkey: str,
    expected_binding: ChannelBinding | None,
    *,
    bundle_item: bool,
) -> Evidence:
    expected_keys = (
        _EVIDENCE_BUNDLE_ITEM_KEYS
        if bundle_item
        else (
            _EVIDENCE_V2_RESPONSE_KEYS
            if expected_binding is not None
            else _EVIDENCE_RESPONSE_KEYS
        )
    )
    _check_exact_keys(response, expected_keys, "evidence component")
    if response["nonce_hex"] != nonce.hex():
        raise RemoteError("evidence response nonce mismatch")
    if response["assigned_hotkey"] != hotkey:
        raise RemoteError("evidence response hotkey mismatch")
    if expected_binding is not None:
        if response.get("report_data_version") != 2:
            raise RemoteError("evidence response has invalid report data version")
        if _response_channel_binding(response) != expected_binding:
            raise RemoteError("evidence response channel binding mismatch")
    kind_raw = response["kind"]
    quote_raw = response["quote_hex"]
    chain_raw = response["cert_chain_hex"]
    jwt = response.get("composite_jwt")
    if (
        not isinstance(kind_raw, str)
        or not _is_hex(quote_raw)
        or not quote_raw
        or len(quote_raw) > 2 * MAX_EVIDENCE_QUOTE_BYTES
    ):
        raise RemoteError("evidence response has invalid quote or kind")
    if (
        not isinstance(chain_raw, list)
        or len(chain_raw) > MAX_EVIDENCE_CERTIFICATES
    ):
        raise RemoteError("evidence response has invalid certificate chain")
    if any(
        not _is_hex(value)
        or not value
        or len(value) > 2 * MAX_EVIDENCE_CERTIFICATE_BYTES
        for value in chain_raw
    ):
        raise RemoteError("evidence response has invalid certificate chain")
    if jwt is not None and (
        not isinstance(jwt, str)
        or not jwt
        or not jwt.isascii()
        or len(jwt) > MAX_COMPOSITE_JWT_BYTES
        or any(ord(character) < 0x20 for character in jwt)
    ):
        raise RemoteError("evidence response has invalid composite JWT")
    try:
        kind = EvidenceKind(kind_raw)
        quote = bytes.fromhex(quote_raw)
        cert_chain = [bytes.fromhex(value) for value in chain_raw]
    except (TypeError, ValueError):
        raise RemoteError("evidence response is invalid") from None
    return Evidence(
        kind=kind,
        quote=quote,
        nonce=nonce,
        miner_hotkey=hotkey,
        cert_chain=cert_chain,
        composite_jwt=jwt,
        report_data_version=2 if expected_binding is not None else 1,
        channel_binding=expected_binding,
    )


def _validate_work_item(item: SatWorkItem) -> None:
    if not isinstance(item, SatWorkItem):
        raise RemoteError("invalid SAT work item")
    if not _is_sha256(item.challenge_id):
        raise RemoteError("invalid SAT challenge_id")
    if (
        isinstance(item.seed, bool)
        or not isinstance(item.seed, int)
        or not MIN_SEED <= item.seed <= MAX_SEED
    ):
        raise RemoteError("invalid SAT seed")
    _validate_instance(item.instance)
    if _compute_challenge_id(item.instance, item.seed) != item.challenge_id:
        raise RemoteError("invalid SAT challenge_id")


def _validate_instance(instance: SatInstance) -> None:
    if not isinstance(instance, SatInstance):
        raise RemoteError("invalid SAT instance")
    n_vars = instance.n_vars
    clauses = instance.clauses
    if isinstance(n_vars, bool) or not isinstance(n_vars, int) or not 1 <= n_vars <= MAX_N_VARS:
        raise RemoteError("invalid SAT n_vars")
    if not isinstance(clauses, list) or len(clauses) > MAX_CLAUSES:
        raise RemoteError("invalid SAT clauses")

    literal_count = 0
    for clause in clauses:
        if not isinstance(clause, list) or len(clause) > MAX_LITERALS_PER_CLAUSE:
            raise RemoteError("invalid SAT clause")
        literal_count += len(clause)
        if literal_count > MAX_LITERALS:
            raise RemoteError("SAT instance exceeds literal limit")
        for literal in clause:
            if (
                isinstance(literal, bool)
                or not isinstance(literal, int)
                or literal == 0
                or abs(literal) > n_vars
            ):
                raise RemoteError("invalid SAT literal")


def _validate_assignment(assignment: Any, n_vars: int) -> None:
    if not isinstance(assignment, list) or len(assignment) != n_vars:
        raise RemoteError("sat-work response has invalid assignment")
    variables: set[int] = set()
    for literal in assignment:
        if (
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal == 0
            or abs(literal) > n_vars
            or abs(literal) in variables
        ):
            raise RemoteError("sat-work response has invalid assignment")
        variables.add(abs(literal))


def _check_exact_keys(obj: dict[str, Any], expected: frozenset[str], context: str) -> None:
    if set(obj) != expected:
        raise RemoteError(f"{context} has invalid schema")


def _is_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) % 2 == 0
        and value.isascii()
        and all(char in _HEX_DIGITS for char in value)
    )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and _is_hex(value)
