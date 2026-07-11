"""RemoteMiner: typed client for the miner HTTP worker (cathedral/worker.py).

Ties every request to a single enrolled hotkey so a worker cannot answer
on behalf of a different identity. Verifies nonce / hotkey / challenge_id
before constructing typed objects, and never trusts the server's
``work_units`` claim (recomputes from the instance we dispatched).

stdlib-only: urllib.request, json. No third-party dependencies.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from cathedral.common import Evidence, EvidenceKind
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem

MAX_RESPONSE_BODY: int = 128 * 1024  # 128 KiB

# Exact allowed key sets for strict response schema validation.
_EVIDENCE_RESPONSE_KEYS: frozenset[str] = frozenset(
    {"kind", "quote_hex", "nonce_hex", "miner_hotkey", "cert_chain_hex"}
)
_SAT_RESPONSE_KEYS: frozenset[str] = frozenset(
    {"satisfiable", "assignment", "work_units", "challenge_id", "miner_hotkey"}
)


class RemoteError(Exception):
    """Raised when the remote worker returns an unexpected or invalid response."""


class RemoteMiner:
    """Typed proxy to a running WorkerServer.

    Parameters
    ----------
    endpoint:
        Base URL of the worker, e.g. ``"http://127.0.0.1:8080"``.
    hotkey:
        The miner's enrolled hotkey. Sent with every request and verified
        against every response before a typed object is returned.
    bearer_token:
        If set, sent as ``Authorization: Bearer <token>`` on every request.
    timeout:
        Per-request socket timeout in seconds (default 10).
    max_response_body:
        Cap on response body bytes (default 128 KiB). Oversized → :exc:`RemoteError`.
    """

    def __init__(
        self,
        endpoint: str,
        hotkey: str,
        *,
        bearer_token: str | None = None,
        timeout: float = 10.0,
        max_response_body: int = MAX_RESPONSE_BODY,
    ) -> None:
        if not hotkey:
            raise ValueError("hotkey must be non-empty")
        self._endpoint = endpoint.rstrip("/")
        self._hotkey = hotkey
        self._bearer_token = bearer_token
        self._timeout = timeout
        self._max_response_body = max_response_body

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_evidence(self, nonce: bytes) -> Evidence:
        """POST /v1/evidence → :class:`~cathedral.common.Evidence` bound to *nonce*.

        Verifies that the response echoes the original nonce hex and the
        enrolled hotkey before constructing the typed object.

        Raises
        ------
        RemoteError
            On HTTP errors, schema violations, nonce/hotkey mismatch, or
            oversized / malformed responses.
        """
        payload: dict[str, Any] = {
            "nonce_hex": nonce.hex(),
            "assigned_hotkey": self._hotkey,
        }
        resp = self._post("/v1/evidence", payload)

        _check_exact_keys(resp, _EVIDENCE_RESPONSE_KEYS, context="evidence response")

        if resp["nonce_hex"] != nonce.hex():
            raise RemoteError(
                f"evidence response nonce mismatch: "
                f"got {resp['nonce_hex']!r}, want {nonce.hex()!r}"
            )
        if resp["miner_hotkey"] != self._hotkey:
            raise RemoteError(
                f"evidence response hotkey mismatch: "
                f"got {resp['miner_hotkey']!r}, want {self._hotkey!r}"
            )

        try:
            kind = EvidenceKind(resp["kind"])
            quote = bytes.fromhex(resp["quote_hex"])
            cert_chain = [bytes.fromhex(h) for h in resp["cert_chain_hex"]]
        except (ValueError, TypeError, AttributeError) as exc:
            raise RemoteError(f"evidence response decode error: {exc}") from exc

        return Evidence(
            kind=kind,
            quote=quote,
            nonce=nonce,           # use our nonce, not whatever the server echoed
            miner_hotkey=self._hotkey,  # use enrolled hotkey
            cert_chain=cert_chain,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        """POST /v1/sat-work → :class:`~cathedral.lanes.sat_types.SatCertificate`.

        Verifies challenge_id and hotkey in the response. **Never trusts the
        server's** ``work_units`` **claim** — recomputes it from the instance
        we dispatched so a compromised worker cannot inflate its score.

        Raises
        ------
        RemoteError
            On HTTP errors, schema violations, challenge_id/hotkey mismatch,
            or oversized / malformed responses.
        """
        payload: dict[str, Any] = {
            "challenge_id": item.challenge_id,
            "assigned_hotkey": self._hotkey,
            "instance": {
                "n_vars": item.instance.n_vars,
                "clauses": item.instance.clauses,
            },
            "seed": item.seed,
        }
        resp = self._post("/v1/sat-work", payload)

        _check_exact_keys(resp, _SAT_RESPONSE_KEYS, context="sat-work response")

        if resp["challenge_id"] != item.challenge_id:
            raise RemoteError(
                f"sat-work response challenge_id mismatch: "
                f"got {resp['challenge_id']!r}, want {item.challenge_id!r}"
            )
        if resp["miner_hotkey"] != self._hotkey:
            raise RemoteError(
                f"sat-work response hotkey mismatch: "
                f"got {resp['miner_hotkey']!r}, want {self._hotkey!r}"
            )

        satisfiable = resp["satisfiable"]
        assignment = resp["assignment"]

        if not isinstance(satisfiable, bool):
            raise RemoteError("sat-work response: satisfiable must be bool")
        if satisfiable and not isinstance(assignment, list):
            raise RemoteError("sat-work response: assignment must be list when satisfiable=true")
        if not satisfiable and assignment is not None:
            raise RemoteError("sat-work response: assignment must be null when satisfiable=false")

        # Recompute work_units from the instance we sent — ignore server's value.
        validator_work_units = float(len(item.instance.clauses))

        return SatCertificate(
            satisfiable=satisfiable,
            assignment=assignment,
            work_units=validator_work_units,
            challenge_id=item.challenge_id,
            miner_hotkey=self._hotkey,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = self._endpoint + path
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        if self._bearer_token:
            req.add_header("Authorization", f"Bearer {self._bearer_token}")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                raw = response.read(self._max_response_body + 1)
                if len(raw) > self._max_response_body:
                    raise RemoteError(
                        f"response body exceeds cap of {self._max_response_body} bytes"
                    )
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise RemoteError(f"non-JSON response from {url}") from exc
        except urllib.error.HTTPError as exc:
            raw_err = exc.read(4096)
            try:
                detail = json.loads(raw_err).get("error", "")
            except Exception:
                detail = raw_err.decode(errors="replace")[:200]
            raise RemoteError(f"HTTP {exc.code} from {url}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RemoteError(f"connection error to {url}: {exc.reason}") from exc


def _check_exact_keys(obj: Any, expected: frozenset[str], *, context: str) -> None:
    """Raise :exc:`RemoteError` if *obj* does not have exactly *expected* keys."""
    if not isinstance(obj, dict):
        raise RemoteError(f"{context}: expected JSON object, got {type(obj).__name__}")
    got = set(obj.keys())
    if got == expected:
        return
    extra = sorted(got - expected)
    missing = sorted(expected - got)
    parts: list[str] = []
    if missing:
        parts.append(f"missing {missing}")
    if extra:
        parts.append(f"unexpected {extra}")
    raise RemoteError(f"{context}: schema violation — {'; '.join(parts)}")
