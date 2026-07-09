"""Miner enrollment registry and public attestation board.

Small stdlib HTTP service:

    python -m cathedral.enroll --db cathedral-enroll.sqlite --host 127.0.0.1 --port 8080

The trust topology stays inverted: miners enroll an endpoint, then validators
fetch evidence from that miner-owned endpoint.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
from wsgiref.simple_server import make_server

from cathedral.common import Attested

try:
    from substrateinterface import Keypair
except Exception:  # pragma: no cover - exercised only when dependency import fails
    Keypair = None  # type: ignore[assignment]


HOTKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
ENROLL_NONCE_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
MAX_BODY = 16 * 1024
DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 60
DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS = 10 * 60
VERIFICATION_TTL_ENV = "CATHEDRAL_VERIFICATION_TTL_SECONDS"
ENROLL_SIGNATURE_TTL_ENV = "CATHEDRAL_ENROLL_SIGNATURE_TTL_SECONDS"
REJECTED_HOSTS = {"localhost", "metadata.google.internal"}


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _positive_int_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _parse_iso_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601 UTC") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def validate_hotkey(hotkey: object) -> str:
    if not isinstance(hotkey, str) or not HOTKEY_RE.fullmatch(hotkey):
        raise ValueError("hotkey must be a 32-128 character ss58/base58-like string")
    return hotkey


def validate_enroll_nonce(nonce: object) -> str:
    if not isinstance(nonce, str) or not ENROLL_NONCE_RE.fullmatch(nonce):
        raise ValueError("nonce must be a 16-64 byte hex string")
    return nonce.lower()


def validate_enroll_timestamp(
    timestamp: object,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS,
) -> str:
    if not isinstance(timestamp, str):
        raise ValueError("timestamp must be an ISO-8601 UTC string")
    parsed = _parse_iso_utc(timestamp)
    current = now if now is not None else datetime.now(UTC)
    age = abs((current - parsed).total_seconds())
    if age > max_age_seconds:
        raise ValueError("timestamp is outside the enrollment signature window")
    return timestamp


def validate_endpoint_url(endpoint_url: object) -> str:
    if not isinstance(endpoint_url, str):
        raise ValueError("endpoint_url must be a string")
    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("endpoint_url must use http or https")
    if not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("endpoint_url must include a host and no credentials")
    if parsed.fragment:
        raise ValueError("endpoint_url must not include a fragment")
    host = parsed.hostname
    if host is None:
        raise ValueError("endpoint_url must include a host")
    normalized_host = host.rstrip(".").lower()
    if "%" in normalized_host or normalized_host in REJECTED_HOSTS:
        raise ValueError("endpoint_url host is not allowed")
    try:
        ip = ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        if not ip.is_global:
            raise ValueError("endpoint_url host must be a public address")
    return endpoint_url


def canonical_enroll_payload(hotkey: str, endpoint_url: str, nonce: str, timestamp: str) -> bytes:
    """Canonical bytes miners sign before calling /v1/enroll."""

    payload = {
        "endpoint_url": endpoint_url,
        "hotkey": hotkey,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_enroll_signature(hotkey: str, message: bytes, signature_b64: object) -> None:
    if Keypair is None:
        raise ValueError("sr25519 signature verifier unavailable")
    if not isinstance(signature_b64, str):
        raise ValueError("signature_b64 is required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature_b64 must be valid base64") from exc
    if len(signature) != 64:
        raise ValueError("signature_b64 must decode to a 64 byte sr25519 signature")
    try:
        ok = Keypair(ss58_address=hotkey).verify(message, signature)
    except Exception as exc:
        raise ValueError("invalid enroll signature") from exc
    if not ok:
        raise ValueError("invalid enroll signature")


@dataclass(frozen=True)
class Enrollment:
    hotkey: str
    endpoint_url: str


class RegistryStore:
    def __init__(self, path: str, *, verification_ttl_seconds: int | None = None) -> None:
        self.path = path
        if verification_ttl_seconds is None:
            verification_ttl_seconds = _positive_int_from_env(
                VERIFICATION_TTL_ENV,
                DEFAULT_VERIFICATION_TTL_SECONDS,
            )
        if verification_ttl_seconds <= 0:
            raise ValueError("verification_ttl_seconds must be positive")
        self.verification_ttl_seconds = verification_ttl_seconds
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrollments (
                    hotkey TEXT PRIMARY KEY,
                    endpoint_url TEXT NOT NULL,
                    enrolled_at_iso TEXT NOT NULL,
                    updated_at_iso TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attestations (
                    hotkey TEXT PRIMARY KEY,
                    chip_id TEXT,
                    tier TEXT,
                    verification_status TEXT NOT NULL,
                    last_verified_iso TEXT NOT NULL,
                    error TEXT,
                    FOREIGN KEY(hotkey) REFERENCES enrollments(hotkey)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS attestations_chip_id_idx
                ON attestations(chip_id)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enroll_nonces (
                    hotkey TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    used_at_iso TEXT NOT NULL,
                    PRIMARY KEY(hotkey, nonce)
                )
                """
            )

    def enroll(self, hotkey: str, endpoint_url: str, *, nonce: str | None = None) -> None:
        ts = now_iso()
        with self._connect() as conn:
            if nonce is not None:
                try:
                    conn.execute(
                        """
                        INSERT INTO enroll_nonces(hotkey, nonce, used_at_iso)
                        VALUES (?, ?, ?)
                        """,
                        (hotkey, nonce, ts),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError("enroll nonce already used") from exc
            conn.execute(
                """
                INSERT INTO enrollments(hotkey, endpoint_url, enrolled_at_iso, updated_at_iso)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    endpoint_url=excluded.endpoint_url,
                    updated_at_iso=excluded.updated_at_iso
                """,
                (hotkey, endpoint_url, ts, ts),
            )

    def enrollments(self) -> list[Enrollment]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hotkey, endpoint_url FROM enrollments ORDER BY updated_at_iso, hotkey"
            ).fetchall()
        return [Enrollment(row["hotkey"], row["endpoint_url"]) for row in rows]

    def record_verdict(self, hotkey: str, attested: Attested | None, *, error: str | None = None) -> None:
        ts = now_iso()
        if attested is None:
            status = "FAILED"
            chip_id = None
            tier = None
        else:
            status = attested.verification_status
            chip_id = attested.chip_id
            tier = attested.tier.value
        with self._connect() as conn:
            if status == "VERIFIED" and chip_id is not None:
                existing = conn.execute(
                    """
                    SELECT hotkey FROM attestations
                    WHERE chip_id = ?
                      AND hotkey != ?
                      AND verification_status = 'VERIFIED'
                    ORDER BY last_verified_iso DESC
                    LIMIT 1
                    """,
                    (chip_id, hotkey),
                ).fetchone()
                if existing is not None:
                    status = "FAILED"
                    error = f"chip_id already bound to hotkey {existing['hotkey']}"
            conn.execute(
                """
                INSERT INTO attestations(
                    hotkey, chip_id, tier, verification_status, last_verified_iso, error
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    chip_id=excluded.chip_id,
                    tier=excluded.tier,
                    verification_status=excluded.verification_status,
                    last_verified_iso=excluded.last_verified_iso,
                    error=excluded.error
                """,
                (hotkey, chip_id, tier, status, ts, error),
            )

    def _effective_status(self, status: str, last_verified_iso: str | None, now: datetime) -> str:
        if status != "VERIFIED":
            return status
        if last_verified_iso is None:
            return "STALE"
        try:
            verified_at = _parse_iso_utc(last_verified_iso)
        except ValueError:
            return "STALE"
        cutoff = now - timedelta(seconds=self.verification_ttl_seconds)
        if verified_at < cutoff:
            return "STALE"
        return "VERIFIED"

    def board(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    e.hotkey,
                    a.chip_id,
                    a.tier,
                    COALESCE(a.verification_status, 'PENDING') AS verification_status,
                    a.last_verified_iso
                FROM enrollments e
                LEFT JOIN attestations a ON a.hotkey = e.hotkey
                ORDER BY e.updated_at_iso, e.hotkey
                """
            ).fetchall()

        now = datetime.now(UTC)
        miners = []
        verified_chips: set[str] = set()
        for row in rows:
            chip_id = row["chip_id"]
            status = self._effective_status(
                row["verification_status"],
                row["last_verified_iso"],
                now,
            )
            if status == "VERIFIED" and chip_id is not None:
                verified_chips.add(chip_id)
            miners.append(
                {
                    "hotkey": row["hotkey"],
                    "chip_id_prefix": chip_id[:16] if chip_id else None,
                    "tier": row["tier"],
                    "verification_status": status,
                    "last_verified_iso": row["last_verified_iso"],
                }
            )
        return {"count": len(verified_chips), "miners": miners}


class IpRateLimiter:
    def __init__(self, *, limit: int = 10, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        hits = self._hits[ip]
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


class RegistryApp:
    def __init__(
        self,
        store: RegistryStore,
        limiter: IpRateLimiter | None = None,
        *,
        enroll_signature_ttl_seconds: int | None = None,
    ) -> None:
        self.store = store
        self.limiter = limiter if limiter is not None else IpRateLimiter()
        if enroll_signature_ttl_seconds is None:
            enroll_signature_ttl_seconds = _positive_int_from_env(
                ENROLL_SIGNATURE_TTL_ENV,
                DEFAULT_ENROLL_SIGNATURE_TTL_SECONDS,
            )
        if enroll_signature_ttl_seconds <= 0:
            raise ValueError("enroll_signature_ttl_seconds must be positive")
        self.enroll_signature_ttl_seconds = enroll_signature_ttl_seconds

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        try:
            method = environ.get("REQUEST_METHOD", "GET")
            path = environ.get("PATH_INFO", "")
            if method == "POST" and path == "/v1/enroll":
                return self._enroll(environ, start_response)
            if method == "GET" and path == "/v1/attested":
                return self._json(start_response, 200, self.store.board())
            return self._json(start_response, 404, {"error": "not found"})
        except ValueError as exc:
            return self._json(start_response, 400, {"error": str(exc)})
        except json.JSONDecodeError:
            return self._json(start_response, 400, {"error": "invalid json"})

    def _enroll(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        ip = environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "")).split(",")[0].strip()
        if not self.limiter.allow(ip or "unknown"):
            return self._json(start_response, 429, {"error": "rate limit exceeded"})
        payload = self._read_json(environ)
        hotkey = validate_hotkey(payload.get("hotkey"))
        endpoint_url = validate_endpoint_url(payload.get("endpoint_url"))
        nonce = validate_enroll_nonce(payload.get("nonce"))
        timestamp = validate_enroll_timestamp(
            payload.get("timestamp"),
            max_age_seconds=self.enroll_signature_ttl_seconds,
        )
        verify_enroll_signature(
            hotkey,
            canonical_enroll_payload(hotkey, endpoint_url, nonce, timestamp),
            payload.get("signature_b64"),
        )
        self.store.enroll(hotkey, endpoint_url, nonce=nonce)
        return self._json(start_response, 200, {"status": "enrolled"})

    def _read_json(self, environ: dict[str, Any]) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > MAX_BODY:
            raise ValueError("invalid body size")
        body = environ["wsgi.input"].read(length)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("json body must be an object")
        return payload

    @staticmethod
    def _json(start_response: Any, status: int, payload: dict[str, Any]) -> list[bytes]:
        reason = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            429: "Too Many Requests",
        }.get(status, "OK")
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]


def main() -> None:
    parser = argparse.ArgumentParser(description="Cathedral miner enrollment registry")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    app = RegistryApp(RegistryStore(args.db))
    with make_server(args.host, args.port, app) as server:
        print(f"serving registry on http://{args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
