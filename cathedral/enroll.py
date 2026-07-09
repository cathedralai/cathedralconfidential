"""Miner enrollment registry and public attestation board.

Small stdlib HTTP service:

    python -m cathedral.enroll --db cathedral-enroll.sqlite --host 127.0.0.1 --port 8080

The trust topology stays inverted: miners enroll an endpoint, then validators
fetch evidence from that miner-owned endpoint.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from wsgiref.simple_server import make_server

from cathedral.common import Attested


HOTKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
MAX_BODY = 16 * 1024


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_hotkey(hotkey: object) -> str:
    if not isinstance(hotkey, str) or not HOTKEY_RE.fullmatch(hotkey):
        raise ValueError("hotkey must be a 32-128 character ss58/base58-like string")
    return hotkey


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
    return endpoint_url


@dataclass(frozen=True)
class Enrollment:
    hotkey: str
    endpoint_url: str


class RegistryStore:
    def __init__(self, path: str) -> None:
        self.path = path
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

    def enroll(self, hotkey: str, endpoint_url: str) -> None:
        ts = now_iso()
        with self._connect() as conn:
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
            count = conn.execute(
                """
                SELECT COUNT(DISTINCT chip_id)
                FROM attestations
                WHERE verification_status = 'VERIFIED' AND chip_id IS NOT NULL
                """
            ).fetchone()[0]

        miners = []
        for row in rows:
            chip_id = row["chip_id"]
            miners.append(
                {
                    "hotkey": row["hotkey"],
                    "chip_id_prefix": chip_id[:16] if chip_id else None,
                    "tier": row["tier"],
                    "verification_status": row["verification_status"],
                    "last_verified_iso": row["last_verified_iso"],
                }
            )
        return {"count": count, "miners": miners}


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
    def __init__(self, store: RegistryStore, limiter: IpRateLimiter | None = None) -> None:
        self.store = store
        self.limiter = limiter if limiter is not None else IpRateLimiter()

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
        self.store.enroll(hotkey, endpoint_url)
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
