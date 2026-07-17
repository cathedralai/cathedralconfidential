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
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Protocol
from urllib.parse import urlparse
from wsgiref.simple_server import make_server

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    AssuranceClaims,
    assurance_from_dict,
    empty_assurance_claims,
)
from cathedral.common import Attested
from cathedral.lifecycle import (
    NETWORK_ELIGIBLE_STATES,
    TERMINAL_STATES,
    LifecycleError,
    LifecycleReason,
    LifecycleSnapshot,
    WorkerLifecycleState,
    canonical_utc,
    parse_utc,
    require_transition,
    require_transition_reason,
    retry_delay_seconds,
)

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

DEFAULT_HOTKEY_ENROLL_LIMIT = 20
DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS = 3600
_DEFAULT_REGISTRATION_MAX_AGE_SECONDS = 3600


class RegistrationProvider(Protocol):
    """Gate enrollment to hotkeys registered on the subnet.

    Implementations query the Bittensor metagraph, a local cache, or a
    registry service. Return True (registered), False (not registered), or
    None (cannot confirm right now). None is treated as fail-closed: the
    enrollment is rejected and the miner must retry when the provider is
    available. See docs/DESIGN.md §6.
    """

    def is_registered(self, hotkey: str) -> bool | None:
        ...


# Sentinel distinguishing "content is not valid JSON" from a legitimate
# ``None``/``null`` JSON document (which is valid JSON but not a hotkey list).
_JSON_PARSE_FAILED = object()


class JsonHotkeyRegistrationProvider:
    """RegistrationProvider backed by a local hotkey snapshot file.

    Note: this snapshot-based approach is a deliberately minimal production
    policy — it substitutes a live subnet metagraph query with a rotated
    file to avoid a hard chain-connectivity dependency at launch.

    Supports three formats, tried in this order:
    - JSON array: ``["hotkey1", "hotkey2", ...]``
    - JSON object: ``{"hotkeys": ["hotkey1", "hotkey2", ...]}``
    - Newline-delimited: one hotkey per line; blank lines and ``#`` comments ignored.

    Fail-closed rules (``is_registered`` returns ``None``):
    - File does not exist or cannot be read (``OSError``).
    - File mtime is older than *max_age_seconds* (stale snapshot).
    - File parses as JSON but is not a recognised array/object shape.

    Returns ``True`` when the hotkey is present, ``False`` when absent and
    the file is fresh and readable.  ``None`` always triggers a 403 via the
    existing ``RegistryApp`` fail-closed logic — callers must never treat
    ``None`` as "not registered" and must never treat it as "registered".

    Typical update cycle: rotate the file from a cron job that re-fetches the
    metagraph; the max-age bound ensures a stuck cron is caught within one
    interval instead of silently admitting stale/deregistered hotkeys.
    """

    def __init__(self, path: str, *, max_age_seconds: int) -> None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be a positive integer")
        self.path = path
        self.max_age_seconds = max_age_seconds

    def is_registered(self, hotkey: str) -> bool | None:
        try:
            stat_result = os.stat(self.path)
            age = time.time() - stat_result.st_mtime
            if age > self.max_age_seconds:
                return None  # stale snapshot; fail closed
            with open(self.path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError:
            return None  # missing or unreadable file; fail closed

        hotkeys = self._parse(content)
        if hotkeys is None:
            return None  # malformed content; fail closed
        return hotkey in hotkeys

    def _parse(self, content: str) -> set[str] | None:
        """Parse content as JSON array, JSON object, or newline-delimited list.

        Returns ``None`` on malformed/unrecognised JSON structure. Never raises.
        A valid JSON document that isn't a recognised shape is treated as
        malformed (fail closed) rather than falling back to newline parsing,
        to avoid silently misinterpreting a broken JSON snapshot as an empty
        or partial hotkey list.
        """
        stripped = content.strip()
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = _JSON_PARSE_FAILED
        if data is not _JSON_PARSE_FAILED:
            if isinstance(data, list) and all(isinstance(h, str) for h in data):
                return set(data)
            if (
                isinstance(data, dict)
                and isinstance(data.get("hotkeys"), list)
                and all(isinstance(h, str) for h in data["hotkeys"])
            ):
                return set(data["hotkeys"])
            return None  # recognisable-as-JSON but wrong shape; fail closed
        # Not JSON at all: newline-delimited. Lines starting with '#' are comments.
        return {
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }


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


def validate_endpoint_url(endpoint_url: object, *, require_ip_literal: bool = False) -> str:
    """Validate an enrollment endpoint URL.

    :param require_ip_literal: when True (production mode), the host must be
        a public IP literal. This closes the DNS check/use (TOCTOU) gap for
        launch without a pinned custom connector: a hostname resolved at
        enrollment time could resolve to a different, non-global address by
        the time the prober connects (DNS rebinding). An IP literal has no
        such gap because there is nothing left to resolve. Non-production
        callers may still enroll a hostname endpoint; see ``prober.py`` for
        the matching probe-time gate.
    """
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
        if require_ip_literal:
            raise ValueError(
                "endpoint_url must be a public IP literal in production mode "
                "(hostnames are rejected to close the DNS check/use gap)"
            ) from None
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


@dataclass(frozen=True)
class VerifiedAttestationRecord:
    """Verifier-owned assurance persisted for one enrolled worker."""

    hotkey: str
    chip_id: str
    tier: str
    assurance: AssuranceClaims


class RegistryStore:
    def __init__(
        self,
        path: str,
        *,
        verification_ttl_seconds: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = path
        if verification_ttl_seconds is None:
            verification_ttl_seconds = _positive_int_from_env(
                VERIFICATION_TTL_ENV,
                DEFAULT_VERIFICATION_TTL_SECONDS,
            )
        if (
            isinstance(verification_ttl_seconds, bool)
            or not isinstance(verification_ttl_seconds, int)
            or verification_ttl_seconds <= 0
        ):
            raise ValueError("verification_ttl_seconds must be positive")
        self.verification_ttl_seconds = verification_ttl_seconds
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lifecycle_lock = threading.RLock()
        self._init()

    def _lifecycle_now(self) -> datetime:
        when = self._clock()
        if (
            not isinstance(when, datetime)
            or when.tzinfo is None
            or when.utcoffset() != timedelta(0)
        ):
            raise LifecycleError("worker lifecycle clock must return UTC")
        return when

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            # Serialize schema/backfill clock sampling across RegistryStore
            # instances before any lifecycle timestamp is consumed.
            conn.execute("BEGIN IMMEDIATE")
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
                    assurance_json TEXT,
                    FOREIGN KEY(hotkey) REFERENCES enrollments(hotkey)
                )
                """
            )
            attestation_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(attestations)")
            }
            if "assurance_json" not in attestation_columns:
                conn.execute("ALTER TABLE attestations ADD COLUMN assurance_json TEXT")
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hotkey_enroll_attempts (
                    hotkey TEXT NOT NULL,
                    attempted_at_iso TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS hotkey_enroll_attempts_idx
                ON hotkey_enroll_attempts(hotkey, attempted_at_iso)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hotkey TEXT NOT NULL REFERENCES enrollments(hotkey),
                    generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    evidence_verified_at TEXT,
                    evidence_expires_at TEXT,
                    measurement TEXT,
                    evidence_digest TEXT,
                    policy_digest TEXT,
                    policy_registry_release INTEGER,
                    policy_registry_digest TEXT,
                    retry_count INTEGER NOT NULL,
                    next_retry_at TEXT,
                    operator_detail TEXT,
                    UNIQUE(hotkey, generation, revision)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_current (
                    hotkey TEXT PRIMARY KEY REFERENCES enrollments(hotkey),
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    event_id INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    state_changed_at TEXT NOT NULL,
                    evidence_verified_at TEXT,
                    evidence_expires_at TEXT,
                    measurement TEXT,
                    evidence_digest TEXT,
                    policy_digest TEXT,
                    policy_registry_release INTEGER,
                    policy_registry_digest TEXT,
                    retry_count INTEGER NOT NULL,
                    next_retry_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS worker_lifecycle_events_no_update
                BEFORE UPDATE ON worker_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'worker lifecycle events are append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS worker_lifecycle_events_no_delete
                BEFORE DELETE ON worker_lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'worker lifecycle events are append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS worker_lifecycle_due_idx
                ON worker_lifecycle_current(state, next_retry_at, evidence_expires_at)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS worker_lifecycle_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            self._backfill_lifecycle(conn)

    def _advance_lifecycle_clock(
        self, conn: sqlite3.Connection, when: datetime
    ) -> None:
        encoded = canonical_utc(when)
        row = conn.execute(
            "SELECT last_seen_at FROM worker_lifecycle_clock WHERE singleton = 1"
        ).fetchone()
        if row is None:
            latest = conn.execute(
                "SELECT MAX(state_changed_at) FROM worker_lifecycle_current"
            ).fetchone()[0]
            if isinstance(latest, str) and parse_utc(latest) > when:
                encoded = latest
            conn.execute(
                "INSERT INTO worker_lifecycle_clock(singleton, last_seen_at) VALUES (1, ?)",
                (encoded,),
            )
            if encoded != canonical_utc(when):
                raise LifecycleError("worker lifecycle clock moved backwards")
            return
        last_seen = parse_utc(row["last_seen_at"])
        if when < last_seen:
            raise LifecycleError("worker lifecycle clock moved backwards")
        if when > last_seen:
            conn.execute(
                "UPDATE worker_lifecycle_clock SET last_seen_at = ? WHERE singleton = 1",
                (encoded,),
            )

    def _backfill_lifecycle(self, conn: sqlite3.Connection) -> None:
        when = self._lifecycle_now()
        self._advance_lifecycle_clock(conn, when)
        rows = conn.execute(
            """
            SELECT e.hotkey, a.verification_status, a.last_verified_iso,
                   a.assurance_json
            FROM enrollments e
            LEFT JOIN attestations a ON a.hotkey = e.hotkey
            LEFT JOIN worker_lifecycle_current c ON c.hotkey = e.hotkey
            WHERE c.hotkey IS NULL
            ORDER BY e.hotkey
            """
        ).fetchall()
        for row in rows:
            state = WorkerLifecycleState.PENDING
            reason = LifecycleReason.BACKFILL_PENDING
            evidence_at = None
            expires_at = None
            evidence_digest = None
            policy_digest = None
            if row["verification_status"] == "VERIFIED":
                try:
                    evidence_at = _parse_iso_utc(row["last_verified_iso"])
                except (TypeError, ValueError):
                    state = WorkerLifecycleState.STALE
                    reason = LifecycleReason.BACKFILL_STALE
                else:
                    expires_at = evidence_at + timedelta(
                        seconds=self.verification_ttl_seconds
                    )
                    # Historical rows did not persist the exact measurement,
                    # so migration cannot prove current policy eligibility even
                    # when their old timestamp is still inside the TTL.
                    state = WorkerLifecycleState.STALE
                    reason = LifecycleReason.BACKFILL_STALE
                    assurance = self._stored_assurance(row["assurance_json"])
                    evidence_digest = assurance.hardware.evidence_digest
                    policy_digest = assurance.software.policy_digest
                    if not ATTESTATION_ADMISSION_POLICY.allows(assurance):
                        state = WorkerLifecycleState.FAILED
                        reason = LifecycleReason.VERIFICATION_FAILED
            elif row["verification_status"] is not None:
                state = WorkerLifecycleState.FAILED
                reason = LifecycleReason.VERIFICATION_FAILED
            self._insert_initial_lifecycle(
                conn,
                row["hotkey"],
                state,
                reason,
                when,
                evidence_verified_at=evidence_at,
                evidence_expires_at=expires_at,
                evidence_digest=evidence_digest,
                policy_digest=policy_digest,
            )

    def _insert_initial_lifecycle(
        self,
        conn: sqlite3.Connection,
        hotkey: str,
        state: WorkerLifecycleState,
        reason: LifecycleReason,
        when: datetime,
        *,
        evidence_verified_at: datetime | None = None,
        evidence_expires_at: datetime | None = None,
        evidence_digest: str | None = None,
        policy_digest: str | None = None,
    ) -> None:
        occurred = canonical_utc(when)
        evidence_text = (
            canonical_utc(evidence_verified_at)
            if evidence_verified_at is not None
            else None
        )
        expires_text = (
            canonical_utc(evidence_expires_at)
            if evidence_expires_at is not None
            else None
        )
        cursor = conn.execute(
            """
            INSERT INTO worker_lifecycle_events(
                hotkey, generation, revision, from_state, to_state, reason,
                occurred_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at, operator_detail
            ) VALUES (?, 1, 1, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL, 0, NULL, NULL)
            """,
            (
                hotkey,
                state.value,
                reason.value,
                occurred,
                evidence_text,
                expires_text,
                evidence_digest,
                policy_digest,
            ),
        )
        event_id = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO worker_lifecycle_current(
                hotkey, state, generation, revision, event_id, reason,
                state_changed_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at
            ) VALUES (?, ?, 1, 1, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL, 0, NULL)
            """,
            (
                hotkey,
                state.value,
                event_id,
                reason.value,
                occurred,
                evidence_text,
                expires_text,
                evidence_digest,
                policy_digest,
            ),
        )

    @staticmethod
    def _lifecycle_snapshot_from_row(row: sqlite3.Row) -> LifecycleSnapshot:
        try:
            return LifecycleSnapshot(
                hotkey=row["hotkey"],
                state=WorkerLifecycleState(row["state"]),
                generation=int(row["generation"]),
                revision=int(row["revision"]),
                event_id=int(row["event_id"]),
                reason=LifecycleReason(row["reason"]),
                state_changed_at=parse_utc(row["state_changed_at"]),
                evidence_verified_at=(
                    parse_utc(row["evidence_verified_at"])
                    if row["evidence_verified_at"] is not None
                    else None
                ),
                evidence_expires_at=(
                    parse_utc(row["evidence_expires_at"])
                    if row["evidence_expires_at"] is not None
                    else None
                ),
                measurement=row["measurement"],
                evidence_digest=row["evidence_digest"],
                policy_digest=row["policy_digest"],
                policy_registry_release=row["policy_registry_release"],
                policy_registry_digest=row["policy_registry_digest"],
                retry_count=int(row["retry_count"]),
                next_retry_at=(
                    parse_utc(row["next_retry_at"])
                    if row["next_retry_at"] is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError, LifecycleError) as exc:
            raise LifecycleError("persisted worker lifecycle state is invalid") from exc

    def _lifecycle_row(
        self, conn: sqlite3.Connection, hotkey: str
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM worker_lifecycle_current WHERE hotkey = ?", (hotkey,)
        ).fetchone()
        if row is None:
            raise LifecycleError(f"worker {hotkey!r} has no lifecycle state")
        return row

    def _transition_lifecycle_in_connection(
        self,
        conn: sqlite3.Connection,
        hotkey: str,
        target: WorkerLifecycleState,
        reason: LifecycleReason,
        when: datetime,
        *,
        evidence_verified_at: datetime | None = None,
        evidence_expires_at: datetime | None = None,
        measurement: str | None = None,
        evidence_digest: str | None = None,
        policy_digest: str | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        retry_count: int | None = None,
        next_retry_at: datetime | None = None,
        operator_detail: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        inherit_policy_registry: bool = True,
    ) -> LifecycleSnapshot:
        if not isinstance(target, WorkerLifecycleState) or not isinstance(
            reason, LifecycleReason
        ):
            raise LifecycleError("worker lifecycle transition metadata is invalid")
        for value in (expected_generation, expected_revision):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise LifecycleError("worker lifecycle expectation is invalid")
        if (policy_registry_release is None) != (policy_registry_digest is None):
            raise LifecycleError(
                "worker lifecycle policy registry reference is invalid"
            )
        self._advance_lifecycle_clock(conn, when)
        current = self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )
        if expected_generation is not None and current.generation != expected_generation:
            raise LifecycleError("worker lifecycle generation changed")
        if expected_revision is not None and current.revision != expected_revision:
            raise LifecycleError("worker lifecycle revision changed")
        if when < current.state_changed_at:
            raise LifecycleError("worker lifecycle transition time moved backwards")
        require_transition(current.state, target)
        require_transition_reason(target, reason)
        verified_at = (
            evidence_verified_at
            if evidence_verified_at is not None
            else current.evidence_verified_at
        )
        expires_at = (
            evidence_expires_at
            if evidence_expires_at is not None
            else current.evidence_expires_at
        )
        chosen_measurement = measurement if measurement is not None else current.measurement
        chosen_evidence = (
            evidence_digest if evidence_digest is not None else current.evidence_digest
        )
        chosen_policy = policy_digest if policy_digest is not None else current.policy_digest
        if inherit_policy_registry and policy_registry_release is None:
            chosen_release = current.policy_registry_release
            chosen_registry_digest = current.policy_registry_digest
        else:
            chosen_release = policy_registry_release
            chosen_registry_digest = policy_registry_digest
        retries = current.retry_count if retry_count is None else retry_count
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise LifecycleError("worker lifecycle retry count is invalid")
        if target is WorkerLifecycleState.ATTESTED:
            if (
                verified_at is None
                or expires_at is None
                or verified_at > when
                or expires_at <= when
                or not isinstance(chosen_measurement, str)
                or not chosen_measurement
                or not isinstance(chosen_evidence, str)
                or not isinstance(chosen_policy, str)
            ):
                raise LifecycleError("attested lifecycle state requires fresh evidence")
            if reason is LifecycleReason.ATTESTATION_VERIFIED:
                retries = 0
                next_retry_at = None
        if target in TERMINAL_STATES or target is WorkerLifecycleState.FAILED:
            next_retry_at = None
        if next_retry_at is not None and next_retry_at < when:
            raise LifecycleError("worker lifecycle retry cannot be scheduled in the past")
        detail = operator_detail.strip()[:300] if isinstance(operator_detail, str) else None
        revision = current.revision + 1
        occurred = canonical_utc(when)
        values = {
            "hotkey": hotkey,
            "generation": current.generation,
            "revision": revision,
            "from_state": current.state.value,
            "to_state": target.value,
            "reason": reason.value,
            "occurred_at": occurred,
            "evidence_verified_at": canonical_utc(verified_at) if verified_at else None,
            "evidence_expires_at": canonical_utc(expires_at) if expires_at else None,
            "measurement": chosen_measurement,
            "evidence_digest": chosen_evidence,
            "policy_digest": chosen_policy,
            "policy_registry_release": chosen_release,
            "policy_registry_digest": chosen_registry_digest,
            "retry_count": retries,
            "next_retry_at": canonical_utc(next_retry_at) if next_retry_at else None,
            "operator_detail": detail,
        }
        cursor = conn.execute(
            """
            INSERT INTO worker_lifecycle_events(
                hotkey, generation, revision, from_state, to_state, reason,
                occurred_at, evidence_verified_at, evidence_expires_at,
                measurement, evidence_digest, policy_digest,
                policy_registry_release, policy_registry_digest, retry_count,
                next_retry_at, operator_detail
            ) VALUES (
                :hotkey, :generation, :revision, :from_state, :to_state, :reason,
                :occurred_at, :evidence_verified_at, :evidence_expires_at,
                :measurement, :evidence_digest, :policy_digest,
                :policy_registry_release, :policy_registry_digest, :retry_count,
                :next_retry_at, :operator_detail
            )
            """,
            values,
        )
        event_id = int(cursor.lastrowid)
        updated = conn.execute(
            """
            UPDATE worker_lifecycle_current SET
                state=:to_state, revision=:revision, event_id=:event_id,
                reason=:reason, state_changed_at=:occurred_at,
                evidence_verified_at=:evidence_verified_at,
                evidence_expires_at=:evidence_expires_at,
                measurement=:measurement, evidence_digest=:evidence_digest,
                policy_digest=:policy_digest,
                policy_registry_release=:policy_registry_release,
                policy_registry_digest=:policy_registry_digest,
                retry_count=:retry_count, next_retry_at=:next_retry_at
            WHERE hotkey=:hotkey AND generation=:generation
              AND revision=:prior_revision
            """,
            {**values, "event_id": event_id, "prior_revision": current.revision},
        )
        if updated.rowcount != 1:
            raise LifecycleError("concurrent worker lifecycle transition rejected")
        return self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )

    def transition_lifecycle(
        self,
        hotkey: str,
        target: WorkerLifecycleState,
        reason: LifecycleReason,
        *,
        at: datetime | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        operator_detail: str | None = None,
    ) -> LifecycleSnapshot:
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                target,
                reason,
                when,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
                operator_detail=operator_detail,
            )

    def _materialize_expiry_in_connection(
        self, conn: sqlite3.Connection, hotkey: str, when: datetime
    ) -> LifecycleSnapshot:
        current = self._lifecycle_snapshot_from_row(
            self._lifecycle_row(conn, hotkey)
        )
        if (
            current.state is WorkerLifecycleState.ATTESTED
            and current.evidence_expires_at is not None
            and when >= current.evidence_expires_at
        ):
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                WorkerLifecycleState.STALE,
                LifecycleReason.EVIDENCE_EXPIRED,
                when,
                expected_generation=current.generation,
                expected_revision=current.revision,
            )
        return current

    def lifecycle_snapshot(
        self,
        hotkey: str,
        *,
        at: datetime | None = None,
        materialize_freshness: bool = True,
    ) -> LifecycleSnapshot:
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            if materialize_freshness:
                return self._materialize_expiry_in_connection(conn, hotkey, when)
            return self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )

    def verified_attestation_record(self, hotkey: str) -> VerifiedAttestationRecord:
        """Return the exact verifier result on record, never caller-supplied claims."""

        with self._connect() as conn:
            row = conn.execute(
                "SELECT hotkey,chip_id,tier,verification_status,assurance_json "
                "FROM attestations WHERE hotkey=?",
                (hotkey,),
            ).fetchone()
        if (
            row is None
            or row["verification_status"] != "VERIFIED"
            or not isinstance(row["chip_id"], str)
            or not row["chip_id"]
            or not isinstance(row["tier"], str)
            or not row["tier"]
        ):
            raise LifecycleError("verified attestation record is unavailable")
        assurance = self._stored_assurance(row["assurance_json"])
        if not ATTESTATION_ADMISSION_POLICY.allows(assurance):
            raise LifecycleError("verified attestation record is unavailable")
        return VerifiedAttestationRecord(
            hotkey=row["hotkey"],
            chip_id=row["chip_id"],
            tier=row["tier"],
            assurance=assurance,
        )

    def record_attested_lifecycle(
        self,
        hotkey: str,
        attested: Attested,
        *,
        at: datetime | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> LifecycleSnapshot:
        if not ATTESTATION_ADMISSION_POLICY.allows(attested.assurance):
            raise LifecycleError("attested lifecycle update requires typed admission claims")
        assert attested.assurance is not None
        verified_raw = attested.assurance.hardware.verified_at
        if not isinstance(verified_raw, str):
            raise LifecycleError("attested lifecycle update requires verification time")
        verified_at = _parse_iso_utc(verified_raw)
        expires_at = verified_at + timedelta(seconds=self.verification_ttl_seconds)

        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            if expires_at <= when:
                raise LifecycleError("attested lifecycle update evidence is already stale")
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                WorkerLifecycleState.ATTESTED,
                LifecycleReason.ATTESTATION_VERIFIED,
                when,
                evidence_verified_at=verified_at,
                evidence_expires_at=expires_at,
                measurement=attested.measurement,
                evidence_digest=attested.assurance.hardware.evidence_digest,
                policy_digest=attested.assurance.software.policy_digest,
                policy_registry_release=policy_registry_release,
                policy_registry_digest=policy_registry_digest,
                retry_count=0,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
                inherit_policy_registry=False,
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def record_refresh_failure(
        self,
        hotkey: str,
        *,
        attempt: int,
        maximum_attempts: int,
        at: datetime | None = None,
        retry_base_seconds: int = 5,
        retry_maximum_seconds: int = 300,
        retry_jitter_seconds: int = 5,
        operator_detail: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> LifecycleSnapshot:
        if (
            isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or not 1 <= attempt <= maximum_attempts <= 32
        ):
            raise LifecycleError("worker lifecycle retry attempt is invalid")

        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if expected_generation is not None and current.generation != expected_generation:
                raise LifecycleError("worker lifecycle generation changed")
            if expected_revision is not None and current.revision != expected_revision:
                raise LifecycleError("worker lifecycle revision changed")
            if current.state in TERMINAL_STATES or current.state in {
                WorkerLifecycleState.RETIRING,
                WorkerLifecycleState.FAILED,
            }:
                return current
            exhausted = attempt == maximum_attempts
            if exhausted:
                target = WorkerLifecycleState.FAILED
                reason = LifecycleReason.RETRY_EXHAUSTED
                next_retry = None
            else:
                if (
                    current.state is WorkerLifecycleState.ATTESTED
                    and current.evidence_expires_at is not None
                    and when < current.evidence_expires_at
                ):
                    target = WorkerLifecycleState.ATTESTED
                elif current.state is WorkerLifecycleState.PENDING:
                    target = WorkerLifecycleState.PENDING
                else:
                    target = WorkerLifecycleState.STALE
                reason = LifecycleReason.REFRESH_RETRY
                next_retry = when + timedelta(
                    seconds=retry_delay_seconds(
                        hotkey,
                        current.generation,
                        attempt,
                        base_seconds=retry_base_seconds,
                        maximum_seconds=retry_maximum_seconds,
                        jitter_seconds=retry_jitter_seconds,
                    )
                )
            return self._transition_lifecycle_in_connection(
                conn,
                hotkey,
                target,
                reason,
                when,
                retry_count=attempt,
                next_retry_at=next_retry,
                operator_detail=operator_detail,
                expected_generation=expected_generation,
                expected_revision=expected_revision,
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def due_refreshes(
        self,
        *,
        at: datetime | None = None,
        refresh_ahead_seconds: int = 60,
    ) -> tuple[LifecycleSnapshot, ...]:
        if (
            isinstance(refresh_ahead_seconds, bool)
            or not isinstance(refresh_ahead_seconds, int)
            or refresh_ahead_seconds < 0
        ):
            raise LifecycleError("refresh-ahead window is invalid")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            horizon = when + timedelta(seconds=refresh_ahead_seconds)
            self._advance_lifecycle_clock(conn, when)
            rows = conn.execute(
                "SELECT hotkey FROM worker_lifecycle_current ORDER BY hotkey"
            ).fetchall()
            snapshots = [
                self._materialize_expiry_in_connection(conn, row["hotkey"], when)
                for row in rows
            ]
            return tuple(
                snapshot
                for snapshot in snapshots
                if snapshot.state in NETWORK_ELIGIBLE_STATES
                and (
                    snapshot.next_retry_at is None
                    or snapshot.next_retry_at <= when
                )
                and (
                    snapshot.evidence_expires_at is None
                    or snapshot.evidence_expires_at <= horizon
                )
            )

    def apply_lifecycle_policy(
        self,
        allowed_measurements: set[str] | frozenset[str],
        *,
        at: datetime | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
    ) -> tuple[LifecycleSnapshot, ...]:
        if (
            not isinstance(allowed_measurements, (set, frozenset))
            or any(
                not isinstance(measurement, str) or not measurement
                for measurement in allowed_measurements
            )
        ):
            raise LifecycleError("lifecycle measurement policy is invalid")
        revoked: list[LifecycleSnapshot] = []
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            rows = conn.execute(
                "SELECT * FROM worker_lifecycle_current ORDER BY hotkey"
            ).fetchall()
            for row in rows:
                current = self._lifecycle_snapshot_from_row(row)
                if (
                    current.state in NETWORK_ELIGIBLE_STATES
                    and current.measurement is not None
                    and current.measurement not in allowed_measurements
                ):
                    revoked.append(
                        self._transition_lifecycle_in_connection(
                            conn,
                            current.hotkey,
                            WorkerLifecycleState.REVOKED,
                            LifecycleReason.POLICY_REVOKED,
                            when,
                            policy_registry_release=policy_registry_release,
                            policy_registry_digest=policy_registry_digest,
                            expected_generation=current.generation,
                            expected_revision=current.revision,
                        )
                    )
        return tuple(revoked)

    def reenroll_lifecycle(
        self,
        hotkey: str,
        *,
        reason: LifecycleReason = LifecycleReason.REENROLLED,
        at: datetime | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> LifecycleSnapshot:
        if reason not in {LifecycleReason.REENROLLED, LifecycleReason.ENDPOINT_CHANGED}:
            raise LifecycleError("reenrollment lifecycle reason is invalid")
        def apply(conn: sqlite3.Connection, when: datetime) -> LifecycleSnapshot:
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            generation = current.generation + 1
            occurred = canonical_utc(when)
            cursor = conn.execute(
                """
                INSERT INTO worker_lifecycle_events(
                    hotkey, generation, revision, from_state, to_state, reason,
                    occurred_at, evidence_verified_at, evidence_expires_at,
                    measurement, evidence_digest, policy_digest,
                    policy_registry_release, policy_registry_digest, retry_count,
                    next_retry_at, operator_detail
                ) VALUES (?, ?, 1, ?, 'pending', ?, ?, NULL, NULL, NULL, NULL,
                          NULL, NULL, NULL, 0, NULL, NULL)
                """,
                (hotkey, generation, current.state.value, reason.value, occurred),
            )
            event_id = int(cursor.lastrowid)
            conn.execute(
                """
                UPDATE worker_lifecycle_current SET
                    state='pending', generation=?, revision=1, event_id=?,
                    reason=?, state_changed_at=?, evidence_verified_at=NULL,
                    evidence_expires_at=NULL, measurement=NULL,
                    evidence_digest=NULL, policy_digest=NULL,
                    policy_registry_release=NULL, policy_registry_digest=NULL,
                    retry_count=0, next_retry_at=NULL
                WHERE hotkey=?
                """,
                (generation, event_id, reason.value, occurred, hotkey),
            )
            return self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )

        if connection is not None:
            return apply(connection, at or self._lifecycle_now())
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            return apply(conn, when)

    def retire_lifecycle(
        self,
        hotkey: str,
        *,
        removed: bool = False,
        at: datetime | None = None,
    ) -> LifecycleSnapshot:
        if not isinstance(removed, bool):
            raise LifecycleError("removed must be a boolean")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            when = at or self._lifecycle_now()
            self._advance_lifecycle_clock(conn, when)
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if current.state in TERMINAL_STATES:
                return current
            if current.state is not WorkerLifecycleState.RETIRING:
                current = self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    WorkerLifecycleState.RETIRING,
                    LifecycleReason.OPERATOR_RETIRING,
                    when,
                    expected_generation=current.generation,
                    expected_revision=current.revision,
                )
            if removed:
                current = self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    WorkerLifecycleState.RETIRED,
                    LifecycleReason.WORKER_REMOVED,
                    when,
                    expected_generation=current.generation,
                    expected_revision=current.revision,
                )
            return current

    def lifecycle_history(
        self, hotkey: str, *, operator: bool = False
    ) -> tuple[dict[str, object], ...]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM worker_lifecycle_events WHERE hotkey = ? "
                "ORDER BY event_id",
                (hotkey,),
            ).fetchall()
        history: list[dict[str, object]] = []
        for row in rows:
            event: dict[str, object] = {
                "generation": row["generation"],
                "from_state": row["from_state"],
                "to_state": row["to_state"],
                "reason": row["reason"],
                "occurred_at": row["occurred_at"],
            }
            if operator:
                event.update(
                    {
                        "event_id": row["event_id"],
                        "revision": row["revision"],
                        "evidence_verified_at": row["evidence_verified_at"],
                        "evidence_expires_at": row["evidence_expires_at"],
                        "measurement": row["measurement"],
                        "evidence_digest": row["evidence_digest"],
                        "policy_digest": row["policy_digest"],
                        "policy_registry_release": row["policy_registry_release"],
                        "policy_registry_digest": row["policy_registry_digest"],
                        "retry_count": row["retry_count"],
                        "next_retry_at": row["next_retry_at"],
                        "operator_detail": row["operator_detail"],
                    }
                )
            history.append(event)
        return tuple(history)

    def enroll(self, hotkey: str, endpoint_url: str, *, nonce: str | None = None) -> None:
        ts = now_iso()
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
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

            # Detect whether the endpoint is changing before the upsert so we
            # can clear any stale attestation verdict in the same transaction.
            prior = conn.execute(
                "SELECT endpoint_url FROM enrollments WHERE hotkey = ?", (hotkey,)
            ).fetchone()
            endpoint_changed = prior is not None and prior["endpoint_url"] != endpoint_url

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

            # Changed endpoint: clear the old attestation so the miner returns
            # to PENDING and a fresh probe is required.  Same endpoint: leave
            # the existing verdict intact (idempotent refresh).
            if endpoint_changed:
                conn.execute("DELETE FROM attestations WHERE hotkey = ?", (hotkey,))
                self.reenroll_lifecycle(
                    hotkey,
                    reason=LifecycleReason.ENDPOINT_CHANGED,
                    at=lifecycle_when,
                    connection=conn,
                )
            elif prior is None:
                self._advance_lifecycle_clock(conn, lifecycle_when)
                self._insert_initial_lifecycle(
                    conn,
                    hotkey,
                    WorkerLifecycleState.PENDING,
                    LifecycleReason.ENROLLED,
                    lifecycle_when,
                )

    def check_and_record_hotkey_attempt(
        self, hotkey: str, *, limit: int, window_seconds: int
    ) -> bool:
        """Return False (without recording) if the hotkey exceeds its enrollment
        rate within *window_seconds*. Return True and record the attempt otherwise.

        Backed by SQLite so the bound is durable across process restarts and
        applies consistently across all app instances sharing the same DB file.
        This prevents a miner controlling many valid self-owned hotkeys from
        flooding the probe queue with rapid re-enrollments.
        """
        ts = now_iso()
        cutoff = (
            datetime.now(UTC) - timedelta(seconds=window_seconds)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._connect() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*) FROM hotkey_enroll_attempts
                WHERE hotkey = ? AND attempted_at_iso >= ?
                """,
                (hotkey, cutoff),
            ).fetchone()[0]
            if count >= limit:
                return False
            conn.execute(
                "INSERT INTO hotkey_enroll_attempts(hotkey, attempted_at_iso) VALUES (?, ?)",
                (hotkey, ts),
            )
        return True

    def enrollments(self) -> list[Enrollment]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hotkey, endpoint_url FROM enrollments ORDER BY updated_at_iso, hotkey"
            ).fetchall()
        return [Enrollment(row["hotkey"], row["endpoint_url"]) for row in rows]

    def record_probe_failure(
        self,
        hotkey: str,
        *,
        error: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        maximum_attempts: int = 3,
        retry_base_seconds: int = 5,
        retry_maximum_seconds: int = 300,
        retry_jitter_seconds: int = 5,
    ) -> LifecycleSnapshot:
        """Record a transient probe failure without bypassing bounded retries."""
        if (
            isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or not 1 <= maximum_attempts <= 32
            or isinstance(retry_base_seconds, bool)
            or not isinstance(retry_base_seconds, int)
            or isinstance(retry_maximum_seconds, bool)
            or not isinstance(retry_maximum_seconds, int)
            or not 1 <= retry_base_seconds <= retry_maximum_seconds <= 86400
            or isinstance(retry_jitter_seconds, bool)
            or not isinstance(retry_jitter_seconds, int)
            or not 0 <= retry_jitter_seconds <= retry_maximum_seconds
        ):
            raise LifecycleError("worker lifecycle retry policy is invalid")
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            attempt = min(current.retry_count + 1, maximum_attempts)
            conn.execute(
                """
                INSERT INTO attestations(
                    hotkey, chip_id, tier, verification_status, last_verified_iso,
                    error, assurance_json
                ) VALUES (?, NULL, NULL, 'FAILED', ?, ?, NULL)
                ON CONFLICT(hotkey) DO UPDATE SET
                    chip_id=NULL, tier=NULL, verification_status='FAILED',
                    last_verified_iso=excluded.last_verified_iso,
                    error=excluded.error, assurance_json=NULL
                """,
                (hotkey, now_iso(), error),
            )
            return self.record_refresh_failure(
                hotkey,
                attempt=attempt,
                maximum_attempts=maximum_attempts,
                at=lifecycle_when,
                retry_base_seconds=retry_base_seconds,
                retry_maximum_seconds=retry_maximum_seconds,
                retry_jitter_seconds=retry_jitter_seconds,
                operator_detail=error,
                expected_generation=(
                    current.generation
                    if expected_generation is None
                    else expected_generation
                ),
                expected_revision=(
                    current.revision
                    if expected_revision is None
                    else expected_revision
                ),
                connection=conn,
            )

    def record_verdict(
        self,
        hotkey: str,
        attested: Attested | None,
        *,
        error: str | None = None,
        expected_generation: int | None = None,
        expected_revision: int | None = None,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
        gpu_profile_valid_from: datetime | None = None,
        gpu_profile_valid_until: datetime | None = None,
        gpu_profile_registry_release: int | None = None,
        gpu_profile_registry_digest: str | None = None,
    ) -> None:
        gpu_profile_values = (
            gpu_profile_valid_from,
            gpu_profile_valid_until,
            gpu_profile_registry_release,
            gpu_profile_registry_digest,
        )
        if any(value is not None for value in gpu_profile_values):
            if any(value is None for value in gpu_profile_values):
                raise LifecycleError("GPU profile commit authority is incomplete")
            assert gpu_profile_valid_from is not None
            assert gpu_profile_valid_until is not None
            if (
                not isinstance(gpu_profile_valid_from, datetime)
                or not isinstance(gpu_profile_valid_until, datetime)
                or gpu_profile_valid_from.tzinfo is None
                or gpu_profile_valid_from.utcoffset() != timedelta(0)
                or gpu_profile_valid_until.tzinfo is None
                or gpu_profile_valid_until.utcoffset() != timedelta(0)
                or gpu_profile_valid_from >= gpu_profile_valid_until
                or isinstance(gpu_profile_registry_release, bool)
                or not isinstance(gpu_profile_registry_release, int)
                or gpu_profile_registry_release <= 0
                or not isinstance(gpu_profile_registry_digest, str)
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", gpu_profile_registry_digest
                )
                is None
            ):
                raise LifecycleError("GPU profile commit authority is invalid")
        ts = now_iso()
        if attested is None:
            status = "FAILED"
            chip_id = None
            tier = None
            assurance_json = None
        else:
            status = attested.verification_status
            chip_id = attested.chip_id
            tier = attested.tier.value
            assurance_json = (
                json.dumps(
                    attested.assurance.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if attested.assurance is not None
                else None
            )
        if status == "VERIFIED" and not ATTESTATION_ADMISSION_POLICY.allows(
            attested.assurance if attested is not None else None
        ):
            status = "FAILED"
            chip_id = None
            tier = None
            error = "typed hardware and software assurance claims are required"
        with self._lifecycle_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lifecycle_when = self._lifecycle_now()
            if any(value is not None for value in gpu_profile_values) and (
                status != "VERIFIED"
                or not gpu_profile_valid_from <= lifecycle_when < gpu_profile_valid_until
                or policy_registry_release != gpu_profile_registry_release
                or policy_registry_digest != gpu_profile_registry_digest
            ):
                raise LifecycleError(
                    "GPU profile is not active at lifecycle commit time"
                )
            identity_conflict = False
            if status == "VERIFIED" and chip_id is not None:
                conflict = self._chip_rotation_owner(conn, chip_id, hotkey)
                if conflict is not None:
                    status = "FAILED"
                    chip_id = None
                    tier = None
                    error = f"chip_id already bound to hotkey {conflict}"
                    identity_conflict = True
            conn.execute(
                """
                INSERT INTO attestations(
                    hotkey, chip_id, tier, verification_status, last_verified_iso, error,
                    assurance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hotkey) DO UPDATE SET
                    chip_id=excluded.chip_id,
                    tier=excluded.tier,
                    verification_status=excluded.verification_status,
                    last_verified_iso=excluded.last_verified_iso,
                    error=excluded.error,
                    assurance_json=excluded.assurance_json
                """,
                (hotkey, chip_id, tier, status, ts, error, assurance_json),
            )
            current = self._lifecycle_snapshot_from_row(
                self._lifecycle_row(conn, hotkey)
            )
            if status == "VERIFIED" and attested is not None:
                self.record_attested_lifecycle(
                    hotkey,
                    attested,
                    at=lifecycle_when,
                    expected_generation=(
                        current.generation
                        if expected_generation is None
                        else expected_generation
                    ),
                    expected_revision=(
                        current.revision
                        if expected_revision is None
                        else expected_revision
                    ),
                    policy_registry_release=policy_registry_release,
                    policy_registry_digest=policy_registry_digest,
                    connection=conn,
                )
            elif current.state not in TERMINAL_STATES and current.state is not WorkerLifecycleState.RETIRING:
                self._transition_lifecycle_in_connection(
                    conn,
                    hotkey,
                    (
                        WorkerLifecycleState.REVOKED
                        if identity_conflict
                        else WorkerLifecycleState.FAILED
                    ),
                    (
                        LifecycleReason.IDENTITY_CONFLICT
                        if identity_conflict
                        else LifecycleReason.VERIFICATION_FAILED
                    ),
                    lifecycle_when,
                    operator_detail=error,
                    expected_generation=(
                        current.generation
                        if expected_generation is None
                        else expected_generation
                    ),
                    expected_revision=(
                        current.revision
                        if expected_revision is None
                        else expected_revision
                    ),
                )

    def chip_rotation_owner(self, chip_id: str, hotkey: str) -> str | None:
        """Return the other hotkey currently holding an effective VERIFIED

        binding for ``chip_id``, if any. Callers use this to reject a fresh
        attestation as a same-chip rotation Sybil attempt before admitting
        or scoring it, independent of whether ``record_verdict`` has run for
        this epoch yet.
        """
        with self._connect() as conn:
            return self._chip_rotation_owner(conn, chip_id, hotkey)

    def _chip_rotation_owner(
        self, conn: sqlite3.Connection, chip_id: str, hotkey: str
    ) -> str | None:
        existing = conn.execute(
            """
            SELECT hotkey, last_verified_iso FROM attestations
            WHERE chip_id = ?
              AND hotkey != ?
              AND verification_status = 'VERIFIED'
            ORDER BY last_verified_iso DESC
            LIMIT 1
            """,
            (chip_id, hotkey),
        ).fetchone()
        if existing is None:
            return None
        # Only block rotation when the competing binding is still effective
        # (within TTL). An expired/STALE binding allows a new hotkey to
        # legitimately claim the same physical chip after the previous
        # operator's verification has lapsed.
        now = datetime.now(UTC)
        effective = self._effective_status("VERIFIED", existing["last_verified_iso"], now)
        return existing["hotkey"] if effective == "VERIFIED" else None

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
        if verified_at <= cutoff:
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
                    a.last_verified_iso,
                    a.assurance_json
                FROM enrollments e
                LEFT JOIN attestations a ON a.hotkey = e.hotkey
                ORDER BY e.updated_at_iso, e.hotkey
                """
            ).fetchall()

        miners = []
        verified_chips: set[str] = set()
        for row in rows:
            now = self._lifecycle_now()
            chip_id = row["chip_id"]
            tier = row["tier"]
            assurance = self._stored_assurance(row["assurance_json"])
            status = self._effective_status(
                row["verification_status"],
                row["last_verified_iso"],
                now,
            )
            lifecycle = self.lifecycle_snapshot(row["hotkey"])
            if status == "VERIFIED" and not ATTESTATION_ADMISSION_POLICY.allows(
                assurance
            ):
                status = "FAILED"
                chip_id = None
                tier = None
            if status == "VERIFIED" and chip_id is not None:
                verified_chips.add(chip_id)
            miners.append(
                {
                    "hotkey": row["hotkey"],
                    "chip_id_prefix": chip_id[:16] if chip_id else None,
                    "tier": tier,
                    "verification_status": status,
                    "last_verified_iso": row["last_verified_iso"],
                    "assurance": assurance.to_dict(include_digests=False),
                    "lifecycle": lifecycle.public_dict(),
                }
            )
        return {"count": len(verified_chips), "miners": miners}

    @staticmethod
    def _stored_assurance(raw: str | None) -> AssuranceClaims:
        claims = empty_assurance_claims()
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    claims = assurance_from_dict(parsed)
            except (json.JSONDecodeError, ValueError):
                pass
        return claims


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
        registration_provider: object | None = None,
        production_mode: bool = False,
        trusted_proxy: bool = False,
        hotkey_enroll_limit: int = DEFAULT_HOTKEY_ENROLL_LIMIT,
        hotkey_enroll_window_seconds: int = DEFAULT_HOTKEY_ENROLL_WINDOW_SECONDS,
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
        # Subnet registration gate — injectable so tests can pass stubs without
        # a live chain connection. See RegistrationProvider protocol above.
        self.registration_provider = registration_provider
        # When True, enrollments are rejected if registration cannot be
        # confirmed even when no provider is configured.
        self.production_mode = production_mode
        # When False (default), HTTP_X_FORWARDED_FOR is ignored and rate
        # limiting uses REMOTE_ADDR only.  Set True only when the app runs
        # behind a reverse proxy that sets the header reliably.
        self.trusted_proxy = trusted_proxy
        self.hotkey_enroll_limit = hotkey_enroll_limit
        self.hotkey_enroll_window_seconds = hotkey_enroll_window_seconds

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
        # Never trust X-Forwarded-For unless the app is explicitly configured to
        # run behind a trusted reverse proxy.  A spoofed header lets any client
        # pick an arbitrary source IP and bypass the per-address rate limit.
        if self.trusted_proxy:
            ip = (
                environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", ""))
                .split(",")[0]
                .strip()
            )
        else:
            ip = environ.get("REMOTE_ADDR", "")
        if not self.limiter.allow(ip or "unknown"):
            return self._json(start_response, 429, {"error": "rate limit exceeded"})

        payload = self._read_json(environ)
        hotkey = validate_hotkey(payload.get("hotkey"))
        # Production mode requires a public IP literal endpoint: see
        # validate_endpoint_url for why this replaces a pinned custom
        # connector as the fix for the DNS check/use gap.
        endpoint_url = validate_endpoint_url(
            payload.get("endpoint_url"), require_ip_literal=self.production_mode
        )
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

        # Per-hotkey durable enrollment rate limit. Backed by SQLite so the
        # bound survives restarts and is consistent across app instances that
        # share the same DB.  This prevents a miner controlling many valid
        # self-owned hotkeys from creating an unbounded probe queue.
        if not self.store.check_and_record_hotkey_attempt(
            hotkey,
            limit=self.hotkey_enroll_limit,
            window_seconds=self.hotkey_enroll_window_seconds,
        ):
            return self._json(
                start_response, 429, {"error": "hotkey enrollment rate limit exceeded"}
            )

        # Subnet registration gate: fail closed when a provider is configured
        # or when production_mode=True with no provider.
        if self.registration_provider is not None:
            try:
                registered = self.registration_provider.is_registered(hotkey)
            except Exception:
                registered = None
            if registered is not True:
                return self._json(
                    start_response, 403, {"error": "hotkey not registered on subnet"}
                )
        elif self.production_mode:
            return self._json(
                start_response, 403, {"error": "registration provider not configured"}
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
            403: "Forbidden",
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
    parser.add_argument(
        "--trusted-proxy",
        action="store_true",
        help="trust X-Forwarded-For for rate limiting (only when behind a trusted proxy)",
    )
    parser.add_argument(
        "--production-mode",
        action="store_true",
        help=(
            "launch policy: requires --registered-hotkeys-file and rejects "
            "hostname (non-IP-literal) endpoint_url values at enrollment"
        ),
    )
    parser.add_argument(
        "--registered-hotkeys-file",
        metavar="PATH",
        help=(
            "path to a JSON array, JSON {'hotkeys': [...]} object, or "
            "newline-delimited file of registered hotkeys; used as the "
            "RegistrationProvider. Mandatory when --production-mode is set."
        ),
    )
    parser.add_argument(
        "--registration-max-age-seconds",
        type=int,
        default=_DEFAULT_REGISTRATION_MAX_AGE_SECONDS,
        metavar="N",
        help="reject the hotkey file when its mtime is older than N seconds (default: 3600)",
    )
    args = parser.parse_args()

    if args.registration_max_age_seconds <= 0:
        parser.error("--registration-max-age-seconds must be a positive integer")

    if args.production_mode and not args.registered_hotkeys_file:
        parser.error("--production-mode requires --registered-hotkeys-file")

    provider: RegistrationProvider | None = None
    if args.registered_hotkeys_file:
        provider = JsonHotkeyRegistrationProvider(
            args.registered_hotkeys_file,
            max_age_seconds=args.registration_max_age_seconds,
        )

    app = RegistryApp(
        RegistryStore(args.db),
        trusted_proxy=args.trusted_proxy,
        production_mode=args.production_mode,
        registration_provider=provider,
    )
    with make_server(args.host, args.port, app) as server:
        print(f"serving registry on http://{args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
