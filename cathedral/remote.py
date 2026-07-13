"""Typed, bounded HTTPS-by-default client for a Cathedral miner worker."""
from __future__ import annotations

import json
import math
import socket
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from cathedral.common import Evidence, EvidenceKind
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

MAX_RESPONSE_BODY: int = 128 * 1024
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

        self._endpoint = endpoint.rstrip("/")
        self._hotkey = hotkey
        self._bearer_token = bearer_token
        self._timeout = float(timeout)
        self._max_response_body = max_response_body
        self._opener = urllib.request.build_opener(_RejectRedirects())

    @property
    def uid(self) -> str:
        """The enrolled hotkey, satisfying the validator's miner protocol."""
        return self._hotkey

    def collect_evidence(self, nonce: bytes) -> Evidence:
        """Collect evidence, satisfying the validator's miner protocol."""
        return self.fetch_evidence(nonce)

    def fetch_evidence(self, nonce: bytes) -> Evidence:
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise RemoteError("nonce must be exactly 32 bytes")

        response = self._post(
            "/v1/evidence",
            {"nonce_hex": nonce.hex(), "assigned_hotkey": self._hotkey},
        )
        _check_exact_keys(response, _EVIDENCE_RESPONSE_KEYS, "evidence response")

        if response["nonce_hex"] != nonce.hex():
            raise RemoteError("evidence response nonce mismatch")
        if response["assigned_hotkey"] != self._hotkey:
            raise RemoteError("evidence response hotkey mismatch")

        kind_raw = response["kind"]
        quote_raw = response["quote_hex"]
        chain_raw = response["cert_chain_hex"]
        if not isinstance(kind_raw, str):
            raise RemoteError("evidence response has invalid kind")
        if not _is_hex(quote_raw) or not quote_raw:
            raise RemoteError("evidence response has invalid quote")
        if not isinstance(chain_raw, list) or len(chain_raw) > 16:
            raise RemoteError("evidence response has invalid certificate chain")
        if any(not _is_hex(value) or not value for value in chain_raw):
            raise RemoteError("evidence response has invalid certificate chain")

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
            miner_hotkey=self._hotkey,
            cert_chain=cert_chain,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        _validate_work_item(item)
        response = self._post(
            "/v1/sat-work",
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": self._hotkey,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                },
                "seed": item.seed,
            },
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

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self._bearer_token:
            request.add_header("Authorization", f"Bearer {self._bearer_token}")

        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    if not declared.isascii() or not declared.isdecimal():
                        raise RemoteError("worker response has invalid length")
                    if int(declared) > self._max_response_body:
                        raise RemoteError("worker response exceeds body limit")
                raw = response.read(self._max_response_body + 1)
                if len(raw) > self._max_response_body:
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
