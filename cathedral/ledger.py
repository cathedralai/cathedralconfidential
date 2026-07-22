"""Durable confidential-compute epoch ledger."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol

from cathedral.lanes.sat import (
    CUSTOMER_SAT_WORK_UNITS,
    _compute_challenge_id,
    validate_sat_work_item,
)
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.lifecycle import (
    LifecycleReason,
    LifecycleSnapshot,
    WorkerLifecycleState,
    canonical_utc,
)
from cathedral.receipt import ReceiptError, parse_receipt_json
from cathedral.score_audience import validate_score_audience


class LedgerError(Exception):
    """Raised when a ledger invariant would be violated."""


# Single source of truth for the `epochs` table and its two partial indexes.
# `_migrate_epochs_table_if_needed` below executes each statement individually
# (never via `executescript`) so the rebuild can run inside one explicit,
# rollback-able transaction. The table name is parameterized because the
# migration builds the widened schema under a throwaway temp name (never
# under `epochs` itself -- see that method's docstring for why).
_EPOCHS_MIGRATION_TEMP_PREFIX = "epochs_migration_new_"
_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_CUSTOMER_JOB_RESULT_BYTES = 64 * 1024
_MAX_CUSTOMER_JOB_ERROR_LENGTH = 1000
_CUSTOMER_JOB_IDEMPOTENCY_RE = re.compile(r"[\x21-\x7e]{1,128}")
_CUSTOMER_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
MAX_ACTIVE_CUSTOMER_JOBS = 1024
MAX_ACTIVE_CUSTOMER_JOBS_PER_CUSTOMER = 64
MAX_CUSTOMER_JOB_STORAGE_BYTES = 256 * 1024 * 1024
_GPU_POLICY_MODE_RE = re.compile(
    r"gpu-profile:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"@profile=sha256:[0-9a-f]{64}"
    r"(?:@release=none@registry=none|"
    r"@release=[1-9][0-9]{0,18}@registry=sha256:[0-9a-f]{64})"
)


def _epochs_table_sql(table_name: str) -> str:
    return f"""
CREATE TABLE IF NOT EXISTS {table_name} (
    epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_epoch INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('running', 'aborted', 'complete', 'published', 'abandoned')
    ),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    published_at TEXT,
    generated_at TEXT,
    report_body BLOB,
    report_digest TEXT,
    policy_registry_release INTEGER,
    policy_registry_digest TEXT,
    abandoned_at TEXT,
    abandon_reason TEXT
)
"""


_EPOCHS_TABLE_SQL = _epochs_table_sql("epochs")

_ONE_RUNNING_EPOCH_INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS one_running_epoch ON epochs ((1)) WHERE status = 'running'"
)

_ONE_FINALIZED_SOURCE_EPOCH_INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS one_finalized_source_epoch "
    "ON epochs (source_epoch) WHERE status IN ('complete', 'published')"
)

_SCHEMA = f"""
{_EPOCHS_TABLE_SQL};
{_ONE_RUNNING_EPOCH_INDEX_SQL};
{_ONE_FINALIZED_SOURCE_EPOCH_INDEX_SQL};

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('issued', 'verified', 'failed', 'abandoned')),
    work_units REAL NOT NULL DEFAULT 0 CHECK (work_units >= 0),
    issued_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS epoch_attestations (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict = 'VERIFIED'),
    tee_type TEXT NOT NULL CHECK (tee_type IN ('TDX', 'TDX+GPU_CC')),
    workload TEXT NOT NULL CHECK (workload IN ('CPU', 'GPU')),
    evidence_digest TEXT NOT NULL,
    policy_mode TEXT NOT NULL DEFAULT 'compatibility',
    score_eligible INTEGER NOT NULL CHECK (score_eligible IN (0, 1)),
    attested_at TEXT NOT NULL,
    CHECK (
        (tee_type = 'TDX' AND workload = 'CPU') OR
        (tee_type = 'TDX+GPU_CC' AND workload = 'GPU')
    ),
    PRIMARY KEY (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS epoch_scores (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    work_units REAL NOT NULL CHECK (work_units >= 0),
    score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
    PRIMARY KEY (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS assurance_receipts (
    receipt_id TEXT PRIMARY KEY,
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    challenge_id TEXT NOT NULL UNIQUE REFERENCES challenges(challenge_id),
    work_status TEXT NOT NULL CHECK (work_status IN ('verified', 'failed', 'abandoned')),
    receipt_body BLOB NOT NULL,
    receipt_digest TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    UNIQUE (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS score_class_exports (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    source_epoch INTEGER NOT NULL,
    network TEXT NOT NULL,
    netuid INTEGER NOT NULL CHECK (netuid >= 0),
    class_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    report_body BLOB NOT NULL,
    report_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (epoch_id, network, netuid, class_id, source_id),
    UNIQUE (source_epoch, network, netuid, class_id, source_id)
);

CREATE TABLE IF NOT EXISTS epoch_worker_lifecycle (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence_expires_at TEXT,
    evidence_digest TEXT,
    policy_digest TEXT,
    snapshot_at TEXT NOT NULL,
    PRIMARY KEY (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS customer_jobs (
    job_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    idempotency_key TEXT,
    payload_body BLOB NOT NULL,
    payload_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'leased', 'succeeded', 'failed')),
    submitted_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_token TEXT,
    lease_owner TEXT,
    lease_epoch_id INTEGER REFERENCES epochs(epoch_id),
    lease_challenge_id TEXT REFERENCES challenges(challenge_id),
    lease_expires_at TEXT,
    result_body BLOB,
    result_digest TEXT,
    last_error TEXT,
    resolved_at TEXT,
    CHECK (
        (status = 'leased' AND lease_token IS NOT NULL AND lease_owner IS NOT NULL
         AND lease_epoch_id IS NOT NULL AND lease_challenge_id IS NOT NULL
         AND lease_expires_at IS NOT NULL)
        OR
        (status != 'leased' AND lease_token IS NULL AND lease_owner IS NULL
         AND lease_epoch_id IS NULL AND lease_challenge_id IS NULL
         AND lease_expires_at IS NULL)
    ),
    CHECK (
        (status = 'succeeded' AND result_body IS NOT NULL AND result_digest IS NOT NULL
         AND resolved_at IS NOT NULL)
        OR status != 'succeeded'
    ),
    UNIQUE (customer_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS customer_jobs_claim_order
ON customer_jobs(status, available_at, submitted_at, job_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validated_generated_at(value: str | None) -> str:
    if value is None:
        return _now()
    if not isinstance(value, str):
        raise LedgerError("generated_at must be a timezone-aware ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = parsed.utcoffset()
    except (TypeError, ValueError, OverflowError) as exc:
        raise LedgerError("generated_at must be a timezone-aware ISO-8601 string") from exc
    if offset is None:
        raise LedgerError("generated_at must be a timezone-aware ISO-8601 string")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _strict_json_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _customer_item_body(item: SatWorkItem) -> bytes:
    try:
        validate_sat_work_item(item)
    except ValueError as exc:
        raise LedgerError(str(exc)) from exc
    return _canonical_json(
        {
            "challenge_id": item.challenge_id,
            "clauses": item.instance.clauses,
            "n_vars": item.instance.n_vars,
            "seed": item.seed,
        }
    )


def _customer_item_from_body(body: bytes, digest: str) -> SatWorkItem:
    if (
        not isinstance(body, bytes)
        or not isinstance(digest, str)
        or "sha256:" + hashlib.sha256(body).hexdigest() != digest
    ):
        raise LedgerError("customer job payload integrity check failed")
    try:
        value = json.loads(body, object_pairs_hook=_strict_json_object_pairs)
        if not isinstance(value, dict) or set(value) != {
            "challenge_id",
            "clauses",
            "n_vars",
            "seed",
        }:
            raise ValueError
        item = SatWorkItem(
            instance=SatInstance(n_vars=value["n_vars"], clauses=value["clauses"]),
            seed=value["seed"],
            challenge_id=value["challenge_id"],
        )
        validate_sat_work_item(item)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LedgerError("customer job payload is invalid") from exc
    return item


def _customer_result_body(result: Mapping[str, object] | None) -> bytes | None:
    if result is None:
        return None
    if not isinstance(result, Mapping):
        raise LedgerError("customer job result must be a mapping")
    try:
        body = _canonical_json(dict(result))
    except (TypeError, ValueError) as exc:
        raise LedgerError("customer job result is invalid") from exc
    if not body or len(body) > _MAX_CUSTOMER_JOB_RESULT_BYTES:
        raise LedgerError("customer job result exceeds size limit")
    return body


def _customer_dispatch_item(
    original: SatWorkItem,
    job_id: str,
    attempt: int,
) -> SatWorkItem:
    seed_material = _canonical_json(
        {
            "domain": "cathedral-customer-sat-dispatch-v1",
            "job_id": job_id,
            "attempt": attempt,
            "submitted_seed": original.seed,
        }
    )
    dispatch_seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
    dispatch_seed &= _MAX_SQLITE_INTEGER
    challenge_id = _compute_challenge_id(original.instance, dispatch_seed)
    return SatWorkItem(original.instance, dispatch_seed, challenge_id)


def _validate_customer_result(
    lease: CustomerJobLease,
    result: Mapping[str, object],
) -> None:
    if set(result) != {
        "satisfiable",
        "assignment",
        "work_units",
        "challenge_id",
        "assigned_hotkey",
    }:
        raise LedgerError("customer job result schema is invalid")
    satisfiable = result["satisfiable"]
    assignment = result["assignment"]
    work_units = result["work_units"]
    if (
        not isinstance(satisfiable, bool)
        or result["challenge_id"] != lease.challenge_id
        or result["assigned_hotkey"] != lease.owner_hotkey
        or isinstance(work_units, bool)
        or not isinstance(work_units, (int, float))
        or not math.isfinite(float(work_units))
        or float(work_units) != CUSTOMER_SAT_WORK_UNITS
    ):
        raise LedgerError("customer job result does not match its dispatch")
    if not satisfiable:
        raise LedgerError("customer job success requires a satisfiable assignment witness")
    if not isinstance(assignment, list) or len(assignment) != lease.item.instance.n_vars:
        raise LedgerError("customer job SAT result assignment is invalid")
    if any(isinstance(literal, bool) or not isinstance(literal, int) for literal in assignment):
        raise LedgerError("customer job SAT result assignment is invalid")
    if {abs(literal) for literal in assignment} != set(
        range(1, lease.item.instance.n_vars + 1)
    ):
        raise LedgerError("customer job SAT result assignment is invalid")
    true_literals = set(assignment)
    if any(
        not any(literal in true_literals for literal in clause)
        for clause in lease.item.instance.clauses
    ):
        raise LedgerError("customer job SAT result does not satisfy its instance")


@dataclass(frozen=True)
class CustomerJobLease:
    """Opaque authority to complete one specific customer-job attempt."""

    job_id: str
    lease_token: str
    owner_hotkey: str
    epoch_id: int
    challenge_id: str
    attempt: int
    item: SatWorkItem


@dataclass(frozen=True)
class CustomerJobSnapshot:
    """Customer-safe durable job state."""

    job_id: str
    customer_id: str
    status: str
    attempt_count: int
    item: SatWorkItem
    idempotency_key: str | None = None
    lease_owner: str | None = None
    lease_epoch_id: int | None = None
    result: Mapping[str, object] | None = None
    last_error: str | None = None


def _receipt_lifecycle_values(receipt: Mapping[str, object]) -> tuple[object, ...]:
    lifecycle = receipt.get("lifecycle")
    assurance = receipt.get("assurance")
    if not isinstance(lifecycle, dict) or not isinstance(assurance, dict):
        raise LedgerError("receipt lifecycle snapshot is invalid")
    claims = assurance.get("claims")
    if not isinstance(claims, dict):
        raise LedgerError("receipt lifecycle snapshot is invalid")
    hardware = claims.get("hardware")
    software = claims.get("software")
    if not isinstance(hardware, dict) or not isinstance(software, dict):
        raise LedgerError("receipt lifecycle snapshot is invalid")
    return (
        lifecycle.get("worker_state"),
        lifecycle.get("worker_generation"),
        lifecycle.get("worker_revision"),
        lifecycle.get("worker_event_id"),
        lifecycle.get("worker_reason"),
        lifecycle.get("worker_evidence_expires_at"),
        hardware.get("evidence_digest"),
        software.get("policy_digest"),
    )


def _snapshot_lifecycle_values(snapshot: LifecycleSnapshot) -> tuple[object, ...]:
    return (
        snapshot.state.value,
        snapshot.generation,
        snapshot.revision,
        snapshot.event_id,
        snapshot.reason.value,
        (
            canonical_utc(snapshot.evidence_expires_at)
            if snapshot.evidence_expires_at is not None
            else None
        ),
        snapshot.evidence_digest,
        snapshot.policy_digest,
    )


class ReportPoster(Protocol):
    def post(self, report_body: bytes) -> dict[str, Any]: ...


class Ledger:
    """SQLite ledger with an immutable report snapshot per completed epoch.

    A single connection is retained for the ledger lifetime. This is the anchor
    that keeps a shared in-memory database alive and, together with the lock,
    makes a ledger instance safe to call from multiple threads.
    """

    def __init__(self, db_path: str | Path = ":memory:", *, window_size: int = 3) -> None:
        if window_size < 0:
            raise ValueError("window_size must be nonnegative")
        self.window_size = window_size
        self._lock = threading.RLock()
        self._closed = False
        if str(db_path) == ":memory:":
            target = f"file:cathedral-ledger-{uuid.uuid4().hex}?mode=memory&cache=shared"
            uri = True
        else:
            target = str(db_path)
            uri = False
        self._connection = sqlite3.connect(
            target,
            uri=uri,
            check_same_thread=False,
            isolation_level=None,
            timeout=30,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        if not uri:
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(_SCHEMA)
        self._migrate_epochs_table_if_needed()
        self._migrate_registry_policy_fields_if_needed()
        self._migrate_attestation_policy_mode_if_needed()
        self._migrate_gpu_attestations_if_needed()
        self._migrate_worker_lifecycle_fields_if_needed()

    def _migrate_registry_policy_fields_if_needed(self) -> None:
        columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(epochs)")}
        try:
            if "policy_registry_release" not in columns:
                self._connection.execute(
                    "ALTER TABLE epochs ADD COLUMN policy_registry_release INTEGER"
                )
            if "policy_registry_digest" not in columns:
                self._connection.execute(
                    "ALTER TABLE epochs ADD COLUMN policy_registry_digest TEXT"
                )
        except sqlite3.DatabaseError as exc:
            raise LedgerError("failed to add registry policy audit fields") from exc

    def _migrate_attestation_policy_mode_if_needed(self) -> None:
        """Mark historical attestation rows as compatibility-mode evidence."""

        columns = {
            row["name"] for row in self._connection.execute("PRAGMA table_info(epoch_attestations)")
        }
        if "policy_mode" in columns:
            return
        try:
            self._connection.execute(
                "ALTER TABLE epoch_attestations ADD COLUMN policy_mode TEXT NOT NULL "
                "DEFAULT 'compatibility' CHECK (policy_mode IN ('strict', 'compatibility'))"
            )
        except sqlite3.DatabaseError as exc:
            raise LedgerError("failed to add attestation policy-mode audit field") from exc

    def _migrate_gpu_attestations_if_needed(self) -> None:
        """Widen historical CPU-only attestation rows for typed GPU composites."""

        row = self._connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='epoch_attestations'"
        ).fetchone()
        columns = {
            item["name"]
            for item in self._connection.execute("PRAGMA table_info(epoch_attestations)")
        }
        if row is None or ("TDX+GPU_CC" in row["sql"] and "score_eligible" in columns):
            return
        temporary = f"epoch_attestations_gpu_{uuid.uuid4().hex}"
        previous_foreign_keys = self._connection.execute("PRAGMA foreign_keys").fetchone()[0]
        self._connection.execute("PRAGMA foreign_keys = OFF")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                f"CREATE TABLE {temporary} ("
                "epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),"
                "hotkey TEXT NOT NULL,"
                "verdict TEXT NOT NULL CHECK (verdict = 'VERIFIED'),"
                "tee_type TEXT NOT NULL CHECK (tee_type IN ('TDX','TDX+GPU_CC')),"
                "workload TEXT NOT NULL CHECK (workload IN ('CPU','GPU')),"
                "evidence_digest TEXT NOT NULL,"
                "policy_mode TEXT NOT NULL DEFAULT 'compatibility',"
                "score_eligible INTEGER NOT NULL CHECK(score_eligible IN (0,1)),"
                "attested_at TEXT NOT NULL,"
                "CHECK ((tee_type='TDX' AND workload='CPU') OR "
                "(tee_type='TDX+GPU_CC' AND workload='GPU')),"
                "PRIMARY KEY (epoch_id,hotkey))"
            )
            self._connection.execute(
                f"INSERT INTO {temporary} "
                "SELECT epoch_id,hotkey,verdict,tee_type,workload,evidence_digest,"
                "policy_mode,CASE WHEN tee_type='TDX' AND workload='CPU' THEN 1 ELSE 0 END,"
                "attested_at FROM epoch_attestations"
            )
            self._connection.execute("DROP TABLE epoch_attestations")
            self._connection.execute(f"ALTER TABLE {temporary} RENAME TO epoch_attestations")
            if self._connection.execute("PRAGMA foreign_key_check").fetchall():
                raise LedgerError("GPU attestation ledger migration broke foreign keys")
            self._connection.execute("COMMIT")
        except LedgerError:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        except sqlite3.DatabaseError as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise LedgerError("failed to widen GPU attestation ledger") from exc
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        finally:
            self._connection.execute(
                f"PRAGMA foreign_keys = {'ON' if previous_foreign_keys else 'OFF'}"
            )

    def _migrate_worker_lifecycle_fields_if_needed(self) -> None:
        columns = {
            row["name"]
            for row in self._connection.execute("PRAGMA table_info(epoch_worker_lifecycle)")
        }
        if "evidence_expires_at" in columns:
            return
        try:
            self._connection.execute(
                "ALTER TABLE epoch_worker_lifecycle ADD COLUMN evidence_expires_at TEXT"
            )
        except sqlite3.DatabaseError as exc:
            raise LedgerError("failed to add worker lifecycle evidence-expiry field") from exc

    def _migrate_epochs_table_if_needed(self) -> None:
        """Widen a pre-existing on-disk ``epochs`` table to support 'abandoned'.

        Fresh databases already get the current schema from ``_SCHEMA`` above,
        so this is a no-op for them. Ledgers created before the 'abandoned'
        status existed have an ``epochs`` table whose CHECK constraint and
        column set predate it; SQLite cannot alter a CHECK constraint in
        place, so the table is rebuilt.

        This never renames the live, referenced ``epochs`` table. An earlier
        version of this migration renamed ``epochs`` itself aside (to
        ``epochs_pre_abandon_migration``), rebuilt a fresh ``epochs``, copied
        rows across, then dropped the rename-aside table. On modern SQLite,
        ``ALTER TABLE ... RENAME`` rewrites *other* tables' schema text to
        keep foreign keys pointing at the renamed table -- this rewrite is
        governed by ``PRAGMA legacy_alter_table``, not ``PRAGMA
        foreign_keys``, so setting ``foreign_keys = OFF`` does not suppress
        it. That left ``challenges``/``epoch_attestations``/``epoch_scores``
        and other child tables permanently referencing
        ``epochs_pre_abandon_migration`` in their
        stored schema, and once that table was dropped, every subsequent
        insert into a child table failed with ``no such table: main.
        epochs_pre_abandon_migration`` even though the schema, on its face,
        said ``REFERENCES epochs(epoch_id)`` right up until the rename.

        The fix: build the widened schema under a throwaway, never-referenced
        temp name, copy every row across unchanged (including ``epoch_id``,
        so child rows in ``challenges``, ``epoch_attestations`` and
        ``epoch_scores`` keep pointing at the same logical epoch and so
        SQLite's AUTOINCREMENT high-water mark carries over), drop the old
        ``epochs`` table outright (no rename involved), then rename the temp
        table to ``epochs``. Nothing ever references the temp table's name,
        so the rename-time schema rewrite has nothing to rewrite -- child
        tables' stored SQL keeps saying ``REFERENCES epochs(epoch_id)`` the
        entire time. Indexes are (re)created fresh under the final name after
        the rename.

        The whole rebuild runs inside one explicit ``BEGIN IMMEDIATE`` ...
        ``COMMIT``/``ROLLBACK`` transaction using plain ``execute`` calls (no
        ``executescript``, which implicitly commits and cannot be rolled back
        as a unit). If the process is interrupted or a step fails partway
        through -- including the post-rebuild soundness checks below -- the
        whole create+copy+drop+rename+index transaction rolls back, so
        ``epochs`` is left exactly as it was and no temp table can survive.
        Foreign keys are held off for the duration (SQLite ignores changes to
        that pragma inside a transaction, so it must be toggled outside the
        BEGIN/COMMIT); this is required for ``DROP TABLE epochs`` to succeed
        while child rows still reference it (with foreign keys enabled, SQLite
        treats ``DROP TABLE`` on a referenced parent like a bulk ``DELETE``
        and enforces the FK, which would otherwise raise). The prior pragma
        value is restored on every exit path.

        Before committing, ``PRAGMA foreign_key_check`` must come back empty
        and every child table's stored schema must still mention ``epochs``
        and must not mention the temp table -- if either check fails, the
        transaction is rolled back and a ``LedgerError`` is raised rather than
        persisting a broken schema. The same two checks are repeated once
        more immediately after commit as a defense-in-depth assertion (using
        the same connection, so nothing external could have changed the
        schema in between); a failure there indicates a bug in this method
        itself rather than a recoverable data problem.

        A leftover temp-named table (from an old, interrupted migration --
        either the legacy ``epochs_pre_abandon_migration`` rename-aside name,
        or a temp table from this rebuild's own ``epochs_migration_new_*``
        naming) is refused rather than silently ignored: without this check,
        a fresh ``epochs`` table with the current schema could already exist
        so the ``abandon_reason`` probe below would treat migration as
        already done, and the real history sitting in the leftover table
        would be stranded and never surfaced.
        """
        cx = self._connection
        existing_tables = {
            row["name"] for row in cx.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        leftover_name = next(
            (
                name
                for name in existing_tables
                if name == "epochs_pre_abandon_migration"
                or name.startswith(_EPOCHS_MIGRATION_TEMP_PREFIX)
            ),
            None,
        )
        if leftover_name is not None:
            raise LedgerError(
                f"found leftover {leftover_name!r} table from an interrupted "
                "epochs-table migration; the ledger file needs manual "
                "inspection before it can be reopened"
            )
        columns = {row["name"] for row in cx.execute("PRAGMA table_info(epochs)")}
        if "abandon_reason" in columns:
            return
        temp_name = f"{_EPOCHS_MIGRATION_TEMP_PREFIX}{uuid.uuid4().hex}"
        prior_foreign_keys = cx.execute("PRAGMA foreign_keys").fetchone()[0]
        cx.execute("PRAGMA foreign_keys = OFF")
        try:
            cx.execute("BEGIN IMMEDIATE")
            try:
                cx.execute(_epochs_table_sql(temp_name))
                cx.execute(
                    f"INSERT INTO {temp_name} (epoch_id, source_epoch, status, started_at, "
                    "completed_at, published_at, generated_at, report_body, report_digest) "
                    "SELECT epoch_id, source_epoch, status, started_at, completed_at, "
                    "published_at, generated_at, report_body, report_digest "
                    "FROM epochs"
                )
                cx.execute("DROP TABLE epochs")
                cx.execute(f"ALTER TABLE {temp_name} RENAME TO epochs")
                cx.execute(_ONE_RUNNING_EPOCH_INDEX_SQL)
                cx.execute(_ONE_FINALIZED_SOURCE_EPOCH_INDEX_SQL)
                self._assert_epochs_migration_is_sound(temp_name)
            except BaseException:
                cx.execute("ROLLBACK")
                raise
            else:
                cx.execute("COMMIT")
        except LedgerError:
            raise
        except sqlite3.DatabaseError as exc:
            raise LedgerError(
                "failed to migrate epochs table for the 'abandoned' status; "
                "the ledger file needs manual inspection"
            ) from exc
        finally:
            cx.execute(f"PRAGMA foreign_keys = {'ON' if prior_foreign_keys else 'OFF'}")
        # Defense in depth: re-run the same checks once more now that the
        # rebuild is durably committed. A failure here means this method has
        # a bug, since the pre-commit checks above already passed on the same
        # connection with nothing else able to touch the schema in between.
        self._assert_epochs_migration_is_sound(temp_name)

    def _assert_epochs_migration_is_sound(self, temp_name: str) -> None:
        """Raise ``LedgerError`` unless the epochs rebuild left a sound schema.

        Checks, in order: (1) no foreign key violations anywhere in the
        database, (2) no table's stored schema still mentions the throwaway
        temp table name, and (3) each child table (``challenges``,
        ``epoch_attestations``, ``epoch_scores``) still declares a reference
        to ``epochs``. Called once before COMMIT (so a failure rolls back the
        whole migration) and once more immediately after COMMIT as a
        defense-in-depth assertion.
        """
        cx = self._connection
        violations = cx.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise LedgerError(
                "post-migration PRAGMA foreign_key_check reported violations "
                f"{[tuple(row) for row in violations]!r}; the ledger file "
                "needs manual inspection"
            )
        stray = cx.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE ?",
            (f"%{temp_name}%",),
        ).fetchall()
        if stray:
            raise LedgerError(
                "post-migration schema still references the temporary "
                f"migration table {temp_name!r} in {[row['name'] for row in stray]!r}; "
                "the ledger file needs manual inspection"
            )
        for child_table in (
            "challenges",
            "epoch_attestations",
            "epoch_scores",
            "assurance_receipts",
            "score_class_exports",
            "epoch_worker_lifecycle",
            "customer_jobs",
        ):
            row = cx.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (child_table,),
            ).fetchone()
            if row is None or "epochs" not in row["sql"]:
                raise LedgerError(
                    f"post-migration schema for {child_table!r} no longer "
                    "references 'epochs'; the ledger file needs manual inspection"
                )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def enqueue_customer_job(
        self,
        item: SatWorkItem,
        *,
        customer_id: str = "operator",
        idempotency_key: str | None = None,
    ) -> CustomerJobSnapshot:
        """Persist one bounded customer job, with optional replay-safe submission."""

        if not isinstance(customer_id, str) or _CUSTOMER_ID_RE.fullmatch(customer_id) is None:
            raise LedgerError("customer_id must be a bounded public identifier")
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str)
            or _CUSTOMER_JOB_IDEMPOTENCY_RE.fullmatch(idempotency_key) is None
        ):
            raise LedgerError("idempotency_key must be 1-128 printable non-space ASCII bytes")
        body = _customer_item_body(item)
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        with self._transaction() as cx:
            if idempotency_key is not None:
                existing = cx.execute(
                    "SELECT * FROM customer_jobs WHERE customer_id = ? AND idempotency_key = ?",
                    (customer_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if existing["payload_digest"] != digest:
                        raise LedgerError("idempotency_key was already used for different work")
                    return self._customer_job_snapshot(existing)
            capacity = cx.execute(
                "SELECT COUNT(*) AS total,"
                "SUM(CASE WHEN status IN ('queued','leased') THEN 1 ELSE 0 END) AS active,"
                "COALESCE(SUM(LENGTH(payload_body) + "
                "CASE WHEN status IN ('queued','leased') THEN ? "
                "ELSE COALESCE(LENGTH(result_body),0) END + "
                "COALESCE(LENGTH(last_error),0)),0) AS storage_bytes "
                "FROM customer_jobs",
                (_MAX_CUSTOMER_JOB_RESULT_BYTES,),
            ).fetchone()
            assert capacity is not None
            customer_active = cx.execute(
                "SELECT COUNT(*) FROM customer_jobs WHERE customer_id = ? "
                "AND status IN ('queued','leased')",
                (customer_id,),
            ).fetchone()[0]
            if int(capacity["active"] or 0) >= MAX_ACTIVE_CUSTOMER_JOBS:
                raise LedgerError("customer job queue capacity reached")
            if int(customer_active) >= MAX_ACTIVE_CUSTOMER_JOBS_PER_CUSTOMER:
                raise LedgerError("customer active-job quota reached")
            reserved_bytes = len(body) + _MAX_CUSTOMER_JOB_RESULT_BYTES
            if int(capacity["storage_bytes"] or 0) + reserved_bytes > MAX_CUSTOMER_JOB_STORAGE_BYTES:
                raise LedgerError("customer job ledger storage capacity reached; prune terminal jobs")
            job_id = f"job-{uuid.uuid4().hex}"
            now = _now()
            cx.execute(
                "INSERT INTO customer_jobs("
                "job_id,customer_id,idempotency_key,payload_body,payload_digest,status,"
                "submitted_at,available_at) VALUES (?,?,?,?,?, 'queued',?,?)",
                (job_id, customer_id, idempotency_key, body, digest, now, now),
            )
            row = cx.execute(
                "SELECT * FROM customer_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            assert row is not None
            return self._customer_job_snapshot(row)

    def customer_job(self, job_id: str) -> CustomerJobSnapshot:
        if not isinstance(job_id, str) or re.fullmatch(r"job-[0-9a-f]{32}", job_id) is None:
            raise LedgerError("customer job_id is invalid")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM customer_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"customer job {job_id!r} not found")
            return self._customer_job_snapshot(row)

    def customer_job_counts(self) -> Mapping[str, int]:
        counts = {status: 0 for status in ("queued", "leased", "succeeded", "failed")}
        with self._lock:
            rows = self._connection.execute(
                "SELECT status,COUNT(*) AS count FROM customer_jobs GROUP BY status"
            ).fetchall()
        for row in rows:
            counts[row["status"]] = int(row["count"])
        return MappingProxyType(counts)

    @staticmethod
    def _customer_job_snapshot(row: sqlite3.Row) -> CustomerJobSnapshot:
        result = None
        if row["result_body"] is not None:
            body = row["result_body"]
            digest = row["result_digest"]
            if (
                not isinstance(body, bytes)
                or not isinstance(digest, str)
                or "sha256:" + hashlib.sha256(body).hexdigest() != digest
            ):
                raise LedgerError("customer job result integrity check failed")
            try:
                parsed = json.loads(body, object_pairs_hook=_strict_json_object_pairs)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LedgerError("customer job result is invalid") from exc
            if not isinstance(parsed, dict):
                raise LedgerError("customer job result is invalid")
            result = MappingProxyType(parsed)
        return CustomerJobSnapshot(
            job_id=row["job_id"],
            customer_id=row["customer_id"],
            status=row["status"],
            attempt_count=row["attempt_count"],
            item=_customer_item_from_body(row["payload_body"], row["payload_digest"]),
            idempotency_key=row["idempotency_key"],
            lease_owner=row["lease_owner"],
            lease_epoch_id=row["lease_epoch_id"],
            result=result,
            last_error=row["last_error"],
        )

    def prune_customer_jobs(
        self,
        resolved_before: datetime,
        *,
        limit: int = 1000,
        customer_id: str | None = None,
    ) -> int:
        """Delete bounded terminal history so freed SQLite pages can be reused."""

        if (
            not isinstance(resolved_before, datetime)
            or resolved_before.tzinfo is None
            or resolved_before.utcoffset() != timezone.utc.utcoffset(None)
        ):
            raise LedgerError("resolved_before must be a UTC timestamp")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise LedgerError("prune limit must be between 1 and 10000")
        if customer_id is not None and (
            not isinstance(customer_id, str) or _CUSTOMER_ID_RE.fullmatch(customer_id) is None
        ):
            raise LedgerError("customer_id must be a bounded public identifier")
        before = resolved_before.isoformat()
        with self._transaction() as cx:
            parameters: list[object] = [before]
            customer_clause = ""
            if customer_id is not None:
                customer_clause = " AND customer_id = ?"
                parameters.append(customer_id)
            parameters.append(limit)
            cursor = cx.execute(
                "DELETE FROM customer_jobs WHERE job_id IN ("
                "SELECT job_id FROM customer_jobs "
                "WHERE status IN ('succeeded','failed') AND resolved_at < ?"
                + customer_clause
                + " ORDER BY resolved_at,job_id LIMIT ?)",
                parameters,
            )
            return cursor.rowcount

    def claim_customer_job(
        self,
        owner_hotkey: str,
        epoch_id: int,
        *,
        lease_seconds: int,
        max_attempts: int,
    ) -> CustomerJobLease | None:
        """Atomically reclaim stale work and lease the oldest queued job."""

        if not isinstance(owner_hotkey, str) or not owner_hotkey or len(owner_hotkey) > 256:
            raise LedgerError("customer job owner hotkey is invalid")
        for name, value, maximum in (
            ("lease_seconds", lease_seconds, 86400),
            ("max_attempts", max_attempts, 100),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise LedgerError(f"{name} must be between 1 and {maximum}")
        with self._transaction() as cx:
            self._require_running(cx, epoch_id, "claim customer jobs")
            now_dt = datetime.now(timezone.utc)
            now = now_dt.isoformat()
            expired = cx.execute(
                "SELECT job_id,lease_challenge_id,attempt_count FROM customer_jobs "
                "WHERE status = 'leased' AND lease_expires_at <= ?",
                (now,),
            ).fetchall()
            for stale in expired:
                cx.execute(
                    "UPDATE challenges SET status = 'abandoned',work_units = 0,resolved_at = ? "
                    "WHERE challenge_id = ? AND status = 'issued'",
                    (now, stale["lease_challenge_id"]),
                )
                terminal = stale["attempt_count"] >= max_attempts
                cx.execute(
                    "UPDATE customer_jobs SET status = ?,available_at = ?,lease_token = NULL,"
                    "lease_owner = NULL,lease_epoch_id = NULL,lease_challenge_id = NULL,"
                    "lease_expires_at = NULL,last_error = ?,resolved_at = ? WHERE job_id = ?",
                    (
                        "failed" if terminal else "queued",
                        now,
                        "customer job lease expired",
                        now if terminal else None,
                        stale["job_id"],
                    ),
                )
            cx.execute(
                "UPDATE customer_jobs SET status = 'failed',last_error = ?,resolved_at = ? "
                "WHERE status = 'queued' AND attempt_count >= ?",
                ("customer job retry limit reached", now, max_attempts),
            )
            row = cx.execute(
                "SELECT * FROM customer_jobs WHERE status = 'queued' AND available_at <= ? "
                "AND attempt_count < ? "
                "ORDER BY available_at,submitted_at,job_id LIMIT 1",
                (now, max_attempts),
            ).fetchone()
            if row is None:
                return None
            original = _customer_item_from_body(row["payload_body"], row["payload_digest"])
            attempt = int(row["attempt_count"]) + 1
            item = _customer_dispatch_item(original, row["job_id"], attempt)
            challenge_id = item.challenge_id
            lease_token = uuid.uuid4().hex
            expires_at = (now_dt + timedelta(seconds=lease_seconds)).isoformat()
            try:
                cx.execute(
                    "INSERT INTO challenges(challenge_id,epoch_id,hotkey,status,issued_at) "
                    "VALUES (?,?,?,'issued',?)",
                    (challenge_id, epoch_id, owner_hotkey, now),
                )
                cursor = cx.execute(
                    "UPDATE customer_jobs SET status = 'leased',attempt_count = ?,"
                    "lease_token = ?,lease_owner = ?,lease_epoch_id = ?,"
                    "lease_challenge_id = ?,lease_expires_at = ?,last_error = NULL,"
                    "resolved_at = NULL WHERE job_id = ? AND status = 'queued'",
                    (
                        attempt,
                        lease_token,
                        owner_hotkey,
                        epoch_id,
                        challenge_id,
                        expires_at,
                        row["job_id"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise LedgerError("failed to issue a unique customer job challenge") from exc
            if cursor.rowcount != 1:
                raise LedgerError("customer job claim lost its atomic queue state")
            return CustomerJobLease(
                row["job_id"],
                lease_token,
                owner_hotkey,
                epoch_id,
                challenge_id,
                attempt,
                item,
            )

    def begin_epoch(
        self,
        source_epoch: int,
        *,
        policy_registry_release: int | None = None,
        policy_registry_digest: str | None = None,
    ) -> int:
        """Begin the next attempt, reusing an aborted attempt's source epoch."""
        if isinstance(source_epoch, bool) or not isinstance(source_epoch, int) or source_epoch < 0:
            raise LedgerError("source_epoch must be a nonnegative integer")
        if (policy_registry_release is None) != (policy_registry_digest is None):
            raise LedgerError("policy registry release and digest must be supplied together")
        if policy_registry_release is not None and (
            isinstance(policy_registry_release, bool)
            or not isinstance(policy_registry_release, int)
            or not 0 < policy_registry_release <= _MAX_SQLITE_INTEGER
            or not isinstance(policy_registry_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", policy_registry_digest) is None
        ):
            raise LedgerError("policy registry metadata is invalid")
        with self._transaction() as cx:
            blocking = cx.execute(
                "SELECT epoch_id, status FROM epochs WHERE status IN ('running', 'complete') LIMIT 1"
            ).fetchone()
            if blocking:
                action = "finish" if blocking["status"] == "running" else "publish"
                raise LedgerError(
                    f"epoch {blocking['epoch_id']} is {blocking['status']}; {action} it before beginning"
                )

            last_final = cx.execute(
                "SELECT MAX(source_epoch) AS value FROM epochs "
                "WHERE status IN ('complete', 'published')"
            ).fetchone()["value"]
            retry = cx.execute(
                "SELECT source_epoch FROM epochs WHERE status = 'aborted' "
                "AND (? IS NULL OR source_epoch > ?) ORDER BY epoch_id DESC LIMIT 1",
                (last_final, last_final),
            ).fetchone()
            if retry and source_epoch != retry["source_epoch"]:
                raise LedgerError(
                    f"aborted source_epoch {retry['source_epoch']} must be retried before advancing"
                )
            if last_final is not None and source_epoch <= last_final:
                raise LedgerError(f"source_epoch must be greater than finalized epoch {last_final}")

            cursor = cx.execute(
                "INSERT INTO epochs(source_epoch, status, started_at, "
                "policy_registry_release, policy_registry_digest) "
                "VALUES (?, 'running', ?, ?, ?)",
                (
                    source_epoch,
                    _now(),
                    policy_registry_release,
                    policy_registry_digest,
                ),
            )
            return int(cursor.lastrowid)

    def abort_epoch(self, epoch_id: int) -> None:
        with self._transaction() as cx:
            row = self._epoch(cx, epoch_id)
            if row["status"] == "aborted":
                return
            if row["status"] != "running":
                raise LedgerError(f"epoch {epoch_id} is {row['status']}; cannot abort")
            now = _now()
            leased = cx.execute(
                "SELECT job_id,lease_challenge_id FROM customer_jobs "
                "WHERE status = 'leased' AND lease_epoch_id = ?",
                (epoch_id,),
            ).fetchall()
            for job in leased:
                cx.execute(
                    "UPDATE challenges SET status = 'abandoned',work_units = 0,resolved_at = ? "
                    "WHERE challenge_id = ? AND status = 'issued'",
                    (now, job["lease_challenge_id"]),
                )
                cx.execute(
                    "UPDATE customer_jobs SET status = 'queued',available_at = ?,"
                    "lease_token = NULL,lease_owner = NULL,lease_epoch_id = NULL,"
                    "lease_challenge_id = NULL,lease_expires_at = NULL,"
                    "last_error = ? WHERE job_id = ?",
                    (now, "customer job epoch aborted", job["job_id"]),
                )
            cx.execute("UPDATE epochs SET status = 'aborted' WHERE epoch_id = ?", (epoch_id,))

    def abandon_completed_epoch(self, epoch_id: int, reason: str) -> None:
        """Audited operator recovery for a 'complete' epoch that can never publish.

        Intended for a report that is correctly frozen but has aged past what
        the downstream ingest service will accept for a first publish attempt
        (e.g. a "too old for first ingest" rejection). ``retry-publish`` can
        only ever resend the exact same immutable ``report_body``, so once
        that window has passed the epoch would otherwise block ``begin_epoch``
        forever. This is a one-way, audited status transition only -- it never
        mutates ``report_body``/``report_digest``, and it never makes the
        abandoned work payable: ``mark_published`` only accepts a 'complete'
        epoch, and the trailing score window in ``complete_epoch`` only reads
        'published' epochs, so an 'abandoned' epoch is permanently excluded
        from both.

        Only a 'complete' epoch may transition; every other status (running,
        aborted, published, already abandoned) is an invalid transition and
        raises.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise LedgerError("abandon reason must be a nonempty operator-supplied string")
        with self._transaction() as cx:
            row = self._epoch(cx, epoch_id)
            if row["status"] != "complete":
                raise LedgerError(
                    f"epoch {epoch_id} is {row['status']}; only a complete epoch can be abandoned"
                )
            cx.execute(
                "UPDATE epochs SET status = 'abandoned', abandoned_at = ?, abandon_reason = ? "
                "WHERE epoch_id = ?",
                (_now(), reason.strip(), epoch_id),
            )

    def issue_challenge(self, challenge_id: str, hotkey: str, epoch_id: int) -> None:
        if not challenge_id or not hotkey:
            raise LedgerError("challenge_id and hotkey are required")
        with self._transaction() as cx:
            self._require_running(cx, epoch_id, "issue challenges")
            try:
                cx.execute(
                    "INSERT INTO challenges(challenge_id, epoch_id, hotkey, status, issued_at) "
                    "VALUES (?, ?, ?, 'issued', ?)",
                    (challenge_id, epoch_id, hotkey, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise LedgerError(f"duplicate challenge_id {challenge_id!r}") from exc

    def resolve_challenge(
        self,
        challenge_id: str,
        status: str,
        work_units: float = 0.0,
        *,
        validator_derived: bool = False,
        customer_lease: CustomerJobLease | None = None,
        customer_disposition: str | None = None,
        customer_result: Mapping[str, object] | None = None,
        customer_error: str | None = None,
        customer_max_attempts: int = 3,
    ) -> None:
        units = self._validated_resolution_units(
            status, work_units, validator_derived=validator_derived
        )
        result_body, checked_error = self._validate_customer_resolution(
            status=status,
            lease=customer_lease,
            disposition=customer_disposition,
            result=customer_result,
            error=customer_error,
            max_attempts=customer_max_attempts,
        )
        if customer_lease is not None and customer_lease.challenge_id != challenge_id:
            raise LedgerError("customer lease does not match the resolved challenge")
        with self._transaction() as cx:
            if customer_lease is not None:
                self._require_current_customer_lease(cx, customer_lease)
            self._resolve_challenge_in_transaction(cx, challenge_id, status, units)
            if customer_lease is not None:
                assert customer_disposition is not None
                self._resolve_customer_job_in_transaction(
                    cx,
                    customer_lease,
                    customer_disposition,
                    result_body,
                    checked_error,
                    customer_max_attempts,
                )

    @staticmethod
    def _validated_resolution_units(
        status: str,
        work_units: float,
        *,
        validator_derived: bool,
    ) -> float:
        if status not in {"verified", "failed", "abandoned"}:
            raise LedgerError(f"invalid resolve status {status!r}")
        try:
            units = float(work_units)
        except (TypeError, ValueError) as exc:
            raise LedgerError("work_units must be finite and nonnegative") from exc
        if not math.isfinite(units) or units < 0:
            raise LedgerError("work_units must be finite and nonnegative")
        if status == "verified" and not validator_derived:
            raise LedgerError("verified work_units must be validator-derived")
        return units if status == "verified" else 0.0

    @staticmethod
    def _resolve_challenge_in_transaction(
        cx: sqlite3.Connection,
        challenge_id: str,
        status: str,
        units: float,
    ) -> sqlite3.Row:
        row = cx.execute(
            "SELECT c.status, c.epoch_id, c.hotkey, e.status AS epoch_status "
            "FROM challenges c JOIN epochs e USING(epoch_id) WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            raise LedgerError(f"challenge {challenge_id!r} not found")
        if row["epoch_status"] != "running":
            raise LedgerError("challenge can only be resolved while its epoch is running")
        if row["status"] != "issued":
            raise LedgerError(f"challenge {challenge_id!r} is already {row['status']}")
        cx.execute(
            "UPDATE challenges SET status = ?, work_units = ?, resolved_at = ? "
            "WHERE challenge_id = ?",
            (status, units, _now(), challenge_id),
        )
        return row

    def resolve_challenge_with_receipt(
        self,
        challenge_id: str,
        status: str,
        work_units: float,
        *,
        validator_derived: bool,
        receipt_id: str,
        receipt_body: bytes,
        receipt_digest: str,
        issued_at: str,
        customer_lease: CustomerJobLease | None = None,
        customer_disposition: str | None = None,
        customer_result: Mapping[str, object] | None = None,
        customer_error: str | None = None,
        customer_max_attempts: int = 3,
    ) -> None:
        """Atomically resolve work and freeze its exact signed receipt bytes."""

        units = self._validated_resolution_units(
            status, work_units, validator_derived=validator_derived
        )
        if (
            not isinstance(receipt_id, str)
            or re.fullmatch(r"receipt-sha256:[0-9a-f]{64}", receipt_id) is None
        ):
            raise LedgerError("receipt_id is invalid")
        if not isinstance(receipt_body, bytes) or not receipt_body:
            raise LedgerError("receipt_body must be nonempty bytes")
        if (
            not isinstance(receipt_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_digest) is None
        ):
            raise LedgerError("receipt_digest is invalid")
        if "sha256:" + hashlib.sha256(receipt_body).hexdigest() != receipt_digest:
            raise LedgerError("receipt digest does not match receipt bytes")
        if not isinstance(issued_at, str) or not issued_at:
            raise LedgerError("receipt issued_at is required")
        try:
            receipt = parse_receipt_json(receipt_body)
        except ReceiptError as exc:
            raise LedgerError("receipt body is invalid") from exc
        work = receipt.get("work")
        allowed_claim_statuses = (
            {"passed"} if status == "verified" else {"passed", "failed", "stale", "revoked"}
        )
        if (
            _canonical_json(receipt) != receipt_body
            or receipt.get("receipt_id") != receipt_id
            or receipt.get("issued_at") != issued_at
            or not isinstance(work, dict)
            or work.get("challenge_id") != challenge_id
            or work.get("status") not in allowed_claim_statuses
        ):
            raise LedgerError("receipt body does not match its work resolution")
        receipt_units = work.get("work_units")
        try:
            parsed_units = float(receipt_units)
        except (TypeError, ValueError) as exc:
            raise LedgerError("receipt work units are invalid") from exc
        if not math.isfinite(parsed_units) or parsed_units != units:
            raise LedgerError("receipt work units do not match their resolution")
        result_body, checked_error = self._validate_customer_resolution(
            status=status,
            lease=customer_lease,
            disposition=customer_disposition,
            result=customer_result,
            error=customer_error,
            max_attempts=customer_max_attempts,
        )
        if customer_lease is not None and customer_lease.challenge_id != challenge_id:
            raise LedgerError("customer lease does not match the resolved challenge")
        with self._transaction() as cx:
            if customer_lease is not None:
                self._require_current_customer_lease(cx, customer_lease)
            row = self._resolve_challenge_in_transaction(cx, challenge_id, status, units)
            if (
                receipt.get("epoch_id") != row["epoch_id"]
                or receipt.get("subject_hotkey") != row["hotkey"]
            ):
                raise LedgerError("receipt subject does not match its issued challenge")
            lifecycle = cx.execute(
                "SELECT * FROM epoch_worker_lifecycle WHERE epoch_id = ? AND hotkey = ?",
                (row["epoch_id"], row["hotkey"]),
            ).fetchone()
            if lifecycle is not None:
                expected_lifecycle = (
                    lifecycle["state"],
                    lifecycle["generation"],
                    lifecycle["revision"],
                    lifecycle["event_id"],
                    lifecycle["reason"],
                    lifecycle["evidence_expires_at"],
                    lifecycle["evidence_digest"],
                    lifecycle["policy_digest"],
                )
                if _receipt_lifecycle_values(receipt) != expected_lifecycle:
                    raise LedgerError("receipt does not match the epoch worker lifecycle snapshot")
            try:
                cx.execute(
                    "INSERT INTO assurance_receipts("
                    "receipt_id, epoch_id, hotkey, challenge_id, work_status, "
                    "receipt_body, receipt_digest, issued_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt_id,
                        row["epoch_id"],
                        row["hotkey"],
                        challenge_id,
                        status,
                        receipt_body,
                        receipt_digest,
                        issued_at,
                    ),
                )
            except sqlite3.DatabaseError as exc:
                raise LedgerError("failed to persist receipt atomically") from exc
            if customer_lease is not None:
                assert customer_disposition is not None
                self._resolve_customer_job_in_transaction(
                    cx,
                    customer_lease,
                    customer_disposition,
                    result_body,
                    checked_error,
                    customer_max_attempts,
                )

    @staticmethod
    def _validate_customer_resolution(
        *,
        status: str,
        lease: CustomerJobLease | None,
        disposition: str | None,
        result: Mapping[str, object] | None,
        error: str | None,
        max_attempts: int,
    ) -> tuple[bytes | None, str | None]:
        supplied = (disposition is not None, result is not None, error is not None)
        if lease is None:
            if any(supplied):
                raise LedgerError("customer resolution fields require a customer lease")
            return None, None
        if not isinstance(lease, CustomerJobLease):
            raise LedgerError("customer lease is invalid")
        if disposition not in {"succeeded", "failed", "retry"}:
            raise LedgerError("customer job disposition is invalid")
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or not 1 <= max_attempts <= 100
        ):
            raise LedgerError("customer_max_attempts must be between 1 and 100")
        if disposition == "succeeded":
            if status != "verified" or result is None or error is not None:
                raise LedgerError("successful customer jobs require a verified bounded result")
            _validate_customer_result(lease, result)
        elif status not in {"failed", "abandoned"} or result is not None:
            raise LedgerError("failed or retried customer jobs require a failed resolution")
        if error is not None and (
            not isinstance(error, str)
            or not error.strip()
            or len(error) > _MAX_CUSTOMER_JOB_ERROR_LENGTH
        ):
            raise LedgerError("customer job error must be a bounded nonempty string")
        if disposition in {"failed", "retry"} and error is None:
            raise LedgerError("failed or retried customer jobs require an error")
        return _customer_result_body(result), error.strip() if error is not None else None

    @staticmethod
    def _require_current_customer_lease(
        cx: sqlite3.Connection,
        lease: CustomerJobLease,
    ) -> None:
        row = cx.execute(
            "SELECT * FROM customer_jobs WHERE job_id = ?", (lease.job_id,)
        ).fetchone()
        if row is None:
            raise LedgerError(f"customer job {lease.job_id!r} not found")
        expected = (
            "leased",
            lease.lease_token,
            lease.owner_hotkey,
            lease.epoch_id,
            lease.challenge_id,
            lease.attempt,
        )
        actual = (
            row["status"],
            row["lease_token"],
            row["lease_owner"],
            row["lease_epoch_id"],
            row["lease_challenge_id"],
            row["attempt_count"],
        )
        if actual != expected:
            raise LedgerError("customer job lease is stale or does not match its dispatch")
        original = _customer_item_from_body(row["payload_body"], row["payload_digest"])
        expected_item = _customer_dispatch_item(original, lease.job_id, lease.attempt)
        if lease.item != expected_item:
            raise LedgerError("customer job lease item does not match its durable payload")
        if row["lease_expires_at"] <= _now():
            raise LedgerError("customer job lease has expired")

    @staticmethod
    def _resolve_customer_job_in_transaction(
        cx: sqlite3.Connection,
        lease: CustomerJobLease,
        disposition: str,
        result_body: bytes | None,
        error: str | None,
        max_attempts: int,
    ) -> None:
        now = _now()
        if disposition == "succeeded":
            final_status = "succeeded"
        elif disposition == "retry" and lease.attempt < max_attempts:
            final_status = "queued"
        else:
            final_status = "failed"
        result_digest = (
            "sha256:" + hashlib.sha256(result_body).hexdigest()
            if result_body is not None
            else None
        )
        cursor = cx.execute(
            "UPDATE customer_jobs SET status = ?,available_at = ?,"
            "lease_token = NULL,lease_owner = NULL,lease_epoch_id = NULL,"
            "lease_challenge_id = NULL,lease_expires_at = NULL,result_body = ?,"
            "result_digest = ?,last_error = ?,resolved_at = ? "
            "WHERE job_id = ? AND status = 'leased' AND lease_token = ?",
            (
                final_status,
                now,
                result_body,
                result_digest,
                error,
                None if final_status == "queued" else now,
                lease.job_id,
                lease.lease_token,
            ),
        )
        if cursor.rowcount != 1:
            raise LedgerError("customer job lease changed during atomic resolution")

    def add_attestation(
        self,
        epoch_id: int,
        hotkey: str,
        *,
        verdict: str,
        tee_type: str,
        workload: str,
        evidence_digest: str,
        policy_mode: str = "compatibility",
        score_eligible: bool | None = None,
    ) -> None:
        """Add exact CPU or composite-GPU evidence to a running epoch."""
        hardware_shape = (verdict, tee_type, workload)
        if hardware_shape not in {
            ("VERIFIED", "TDX", "CPU"),
            ("VERIFIED", "TDX+GPU_CC", "GPU"),
        }:
            raise LedgerError("attestation hardware shape is invalid")
        if not hotkey or not evidence_digest:
            raise LedgerError("hotkey and evidence_digest are required")
        if hardware_shape == ("VERIFIED", "TDX", "CPU"):
            valid_policy_mode = policy_mode in {"strict", "compatibility"}
        else:
            valid_policy_mode = _GPU_POLICY_MODE_RE.fullmatch(policy_mode) is not None
        if not valid_policy_mode:
            raise LedgerError("attestation policy_mode does not match its hardware shape")
        if score_eligible is None:
            score_eligible = hardware_shape == ("VERIFIED", "TDX", "CPU")
        if not isinstance(score_eligible, bool):
            raise LedgerError("attestation score eligibility must be a boolean")
        with self._transaction() as cx:
            self._require_running(cx, epoch_id, "add attestations")
            existing = cx.execute(
                "SELECT tee_type,workload,evidence_digest,policy_mode,score_eligible "
                "FROM epoch_attestations "
                "WHERE epoch_id = ? AND hotkey = ?",
                (epoch_id, hotkey),
            ).fetchone()
            if existing:
                if (
                    existing["evidence_digest"] != evidence_digest
                    or existing["policy_mode"] != policy_mode
                    or existing["tee_type"] != tee_type
                    or existing["workload"] != workload
                    or bool(existing["score_eligible"]) is not score_eligible
                ):
                    raise LedgerError("attestation evidence is immutable within an epoch")
                return
            cx.execute(
                "INSERT INTO epoch_attestations "
                "(epoch_id, hotkey, verdict, tee_type, workload, evidence_digest, "
                "policy_mode, score_eligible, attested_at) "
                "VALUES (?, ?, 'VERIFIED', ?, ?, ?, ?, ?, ?)",
                (
                    epoch_id,
                    hotkey,
                    tee_type,
                    workload,
                    evidence_digest,
                    policy_mode,
                    int(score_eligible),
                    _now(),
                ),
            )

    def add_lifecycle_snapshot(
        self,
        epoch_id: int,
        snapshot: LifecycleSnapshot,
        *,
        snapshot_at: str | None = None,
    ) -> None:
        if (
            not isinstance(snapshot, LifecycleSnapshot)
            or not isinstance(snapshot.hotkey, str)
            or not snapshot.hotkey
            or not isinstance(snapshot.state, WorkerLifecycleState)
            or not isinstance(snapshot.reason, LifecycleReason)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _MAX_SQLITE_INTEGER
                for value in (
                    snapshot.generation,
                    snapshot.revision,
                    snapshot.event_id,
                )
            )
        ):
            raise LedgerError("worker lifecycle snapshot is invalid")
        captured_at = _validated_generated_at(snapshot_at)
        snapshot_values = _snapshot_lifecycle_values(snapshot)
        with self._transaction() as cx:
            self._require_running(cx, epoch_id, "add worker lifecycle snapshots")
            existing = cx.execute(
                "SELECT * FROM epoch_worker_lifecycle WHERE epoch_id = ? AND hotkey = ?",
                (epoch_id, snapshot.hotkey),
            ).fetchone()
            values = snapshot_values
            if existing is not None:
                if (
                    tuple(
                        existing[name]
                        for name in (
                            "state",
                            "generation",
                            "revision",
                            "event_id",
                            "reason",
                            "evidence_expires_at",
                            "evidence_digest",
                            "policy_digest",
                        )
                    )
                    != values
                ):
                    raise LedgerError("worker lifecycle snapshot is immutable within an epoch")
                return
            receipt = cx.execute(
                "SELECT receipt_body FROM assurance_receipts WHERE epoch_id = ? AND hotkey = ?",
                (epoch_id, snapshot.hotkey),
            ).fetchone()
            if receipt is not None:
                try:
                    receipt_document = parse_receipt_json(receipt["receipt_body"])
                except ReceiptError as exc:
                    raise LedgerError("stored receipt body is invalid") from exc
                if _receipt_lifecycle_values(receipt_document) != snapshot_values:
                    raise LedgerError("receipt does not match the epoch worker lifecycle snapshot")
            cx.execute(
                """
                INSERT INTO epoch_worker_lifecycle(
                    epoch_id, hotkey, state, generation, revision, event_id,
                    reason, evidence_expires_at, evidence_digest, policy_digest,
                    snapshot_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    epoch_id,
                    snapshot.hotkey,
                    *values,
                    captured_at,
                ),
            )

    def complete_epoch(
        self,
        epoch_id: int,
        all_hotkeys: Iterable[str],
        *,
        generated_at: str | None = None,
        score_authority_valid_until: datetime | None = None,
        score_network: str | None = None,
        score_netuid: int | None = None,
    ) -> dict[str, float]:
        """Freeze scores and canonical report bytes in one durable transaction."""
        stable_generated_at = _validated_generated_at(generated_at)
        audience: tuple[str, int] | None = None
        if score_network is not None or score_netuid is not None:
            try:
                audience = validate_score_audience(score_network, score_netuid)
            except ValueError as exc:
                raise LedgerError(str(exc)) from exc
        if score_authority_valid_until is not None and (
            not isinstance(score_authority_valid_until, datetime)
            or score_authority_valid_until.tzinfo is None
            or score_authority_valid_until.utcoffset() != timezone.utc.utcoffset(None)
        ):
            raise LedgerError("score authority expiry must be a UTC timestamp")
        universe = set(all_hotkeys)
        if any(not isinstance(hotkey, str) or not hotkey for hotkey in universe):
            raise LedgerError("all hotkeys must be nonempty strings")
        with self._transaction() as cx:
            epoch = self._epoch(cx, epoch_id)
            if epoch["status"] in {"complete", "published"}:
                return self._load_scores(cx, epoch_id)
            if epoch["status"] != "running":
                raise LedgerError(f"epoch {epoch_id} is {epoch['status']}; cannot complete")
            unresolved = cx.execute(
                "SELECT COUNT(*) FROM challenges WHERE epoch_id = ? AND status = 'issued'",
                (epoch_id,),
            ).fetchone()[0]
            if unresolved:
                raise LedgerError(f"epoch has {unresolved} unresolved issued challenge(s)")

            universe.update(
                row["hotkey"]
                for row in cx.execute(
                    "SELECT hotkey FROM challenges WHERE epoch_id = ? UNION "
                    "SELECT hotkey FROM epoch_attestations WHERE epoch_id = ?",
                    (epoch_id, epoch_id),
                )
            )
            previous = cx.execute(
                "SELECT epoch_id, source_epoch FROM epochs WHERE status = 'published' "
                "ORDER BY source_epoch DESC LIMIT ?",
                (self.window_size,),
            ).fetchall()
            previous_ids = [row["epoch_id"] for row in previous]
            if previous_ids:
                placeholders = ",".join("?" for _ in previous_ids)
                universe.update(
                    row["hotkey"]
                    for row in cx.execute(
                        f"SELECT DISTINCT hotkey FROM epoch_scores WHERE epoch_id IN ({placeholders})",
                        previous_ids,
                    )
                )

            current_work = {hotkey: 0.0 for hotkey in universe}
            for row in cx.execute(
                "SELECT hotkey, SUM(work_units) AS total FROM challenges "
                "WHERE epoch_id = ? AND status = 'verified' GROUP BY hotkey",
                (epoch_id,),
            ):
                current_work[row["hotkey"]] = float(row["total"])
            totals = dict(current_work)
            current_lanes: dict[str, tuple[str, ...]] = {}
            for row in cx.execute(
                "SELECT hotkey,workload,policy_mode FROM epoch_attestations "
                "WHERE epoch_id = ? AND score_eligible = 1",
                (epoch_id,),
            ):
                current_lanes[row["hotkey"]] = (
                    ("GPU", row["policy_mode"]) if row["workload"] == "GPU" else ("CPU",)
                )
            if previous_ids:
                placeholders = ",".join("?" for _ in previous_ids)
                for row in cx.execute(
                    "SELECT scores.hotkey,scores.work_units,attestations.workload,"
                    "attestations.policy_mode FROM epoch_scores AS scores "
                    "JOIN epoch_attestations AS attestations "
                    "ON attestations.epoch_id=scores.epoch_id "
                    "AND attestations.hotkey=scores.hotkey "
                    f"WHERE scores.epoch_id IN ({placeholders}) "
                    "AND attestations.score_eligible=1",
                    previous_ids,
                ):
                    prior_lane = (
                        ("GPU", row["policy_mode"]) if row["workload"] == "GPU" else ("CPU",)
                    )
                    if current_lanes.get(row["hotkey"]) == prior_lane:
                        totals[row["hotkey"]] = totals.get(row["hotkey"], 0.0) + float(
                            row["work_units"]
                        )

            attested = {
                row["hotkey"]
                for row in cx.execute(
                    "SELECT hotkey FROM epoch_attestations "
                    "WHERE epoch_id = ? AND score_eligible = 1",
                    (epoch_id,),
                )
            }
            policy_modes = sorted(
                {
                    row["policy_mode"]
                    for row in cx.execute(
                        "SELECT policy_mode FROM epoch_attestations WHERE epoch_id = ?",
                        (epoch_id,),
                    )
                }
            )
            lifecycle_rows = cx.execute(
                "SELECT hotkey, state, generation, revision, event_id, reason, "
                "evidence_expires_at, snapshot_at "
                "FROM epoch_worker_lifecycle WHERE epoch_id = ? ORDER BY hotkey",
                (epoch_id,),
            ).fetchall()
            lifecycle_eligible = {
                row["hotkey"]
                for row in lifecycle_rows
                if row["state"] == WorkerLifecycleState.ATTESTED.value
            }
            if lifecycle_rows:
                universe.update(row["hotkey"] for row in lifecycle_rows)
                current_work.update({hotkey: current_work.get(hotkey, 0.0) for hotkey in universe})
                totals.update({hotkey: totals.get(hotkey, 0.0) for hotkey in universe})
                attested &= lifecycle_eligible
            gated = {
                hotkey: units if hotkey in attested else 0.0 for hotkey, units in totals.items()
            }
            current_gated = {
                hotkey: units if hotkey in attested else 0.0
                for hotkey, units in current_work.items()
            }
            maximum = max(gated.values(), default=0.0)
            scores = {
                hotkey: (units / maximum if maximum > 0 else 0.0) for hotkey, units in gated.items()
            }
            report = {
                "complete": True,
                "epoch": epoch["source_epoch"],
                "generated_at": stable_generated_at,
                "mechanism": "cathedral_confidential_tdx",
                "metadata": {
                    "normalization": "max",
                    "attestation_policy_modes": policy_modes,
                    "policy_registry_release": epoch["policy_registry_release"],
                    "policy_registry_digest": epoch["policy_registry_digest"],
                    "published_window_epochs": sorted(row["source_epoch"] for row in previous),
                    "published_window_size": self.window_size,
                    "worker_lifecycle": [
                        {
                            "event_id": row["event_id"],
                            "evidence_expires_at": row["evidence_expires_at"],
                            "generation": row["generation"],
                            "hotkey": row["hotkey"],
                            "reason": row["reason"],
                            "revision": row["revision"],
                            "snapshot_at": row["snapshot_at"],
                            "state": row["state"],
                        }
                        for row in lifecycle_rows
                    ],
                },
                "scores": [
                    {"miner_hotkey": hotkey, "score": scores[hotkey]} for hotkey in sorted(scores)
                ],
                "source": "cathedral_confidential_tdx",
            }
            if audience is not None:
                report["network"], report["netuid"] = audience
            body = _canonical_json(report)
            digest = hashlib.sha256(body).hexdigest()
            completion_time = datetime.now(timezone.utc)
            if (
                score_authority_valid_until is not None
                and completion_time >= score_authority_valid_until
            ):
                raise LedgerError("score authority expired before epoch completion")
            completed_at = completion_time.isoformat()
            cx.execute(
                "UPDATE epochs SET status = 'complete', completed_at = ?, generated_at = ?, "
                "report_body = ?, report_digest = ? WHERE epoch_id = ?",
                (completed_at, stable_generated_at, body, digest, epoch_id),
            )
            cx.executemany(
                "INSERT INTO epoch_scores(epoch_id, hotkey, work_units, score) VALUES (?, ?, ?, ?)",
                [
                    (epoch_id, hotkey, current_gated[hotkey], scores[hotkey])
                    for hotkey in sorted(scores)
                ],
            )
            return scores

    def report_bytes(self, epoch_id: int) -> bytes:
        # 'abandoned' is included so the frozen report of an abandoned epoch
        # stays inspectable for audit purposes; abandonment never mutates or
        # deletes report_body, it only changes the epoch's status.
        with self._lock:
            row = self._epoch(self._connection, epoch_id)
            if (
                row["status"] not in {"complete", "published", "abandoned"}
                or row["report_body"] is None
            ):
                raise LedgerError(f"epoch {epoch_id} has no completed report")
            return bytes(row["report_body"])

    def report_digest(self, epoch_id: int) -> str:
        with self._lock:
            row = self._epoch(self._connection, epoch_id)
            if row["report_digest"] is None:
                raise LedgerError(f"epoch {epoch_id} has no completed report")
            return str(row["report_digest"])

    def mark_published(self, epoch_id: int, report_digest: str | None = None) -> None:
        with self._transaction() as cx:
            row = self._epoch(cx, epoch_id)
            expected = row["report_digest"]
            supplied = report_digest or expected
            if row["status"] == "published":
                if supplied != expected:
                    raise LedgerError("epoch already published with a different digest")
                return
            if row["status"] != "complete":
                raise LedgerError(f"epoch {epoch_id} is {row['status']}; cannot publish")
            if supplied != expected:
                raise LedgerError("published digest does not match persisted report bytes")
            cx.execute(
                "UPDATE epochs SET status = 'published', published_at = ? WHERE epoch_id = ?",
                (_now(), epoch_id),
            )

    def blocking_epoch(self) -> Mapping[str, Any] | None:
        """Return immutable restart data for the sole running/complete epoch."""
        with self._lock:
            row = self._connection.execute(
                "SELECT epoch_id, source_epoch, status, started_at, completed_at, "
                "generated_at, report_digest FROM epochs "
                "WHERE status IN ('running', 'complete') LIMIT 1"
            ).fetchone()
            return MappingProxyType(dict(row)) if row else None

    def pending_epoch(self) -> Mapping[str, Any] | None:
        """Alias for :meth:`blocking_epoch` for restart-oriented callers."""
        return self.blocking_epoch()

    def post_and_mark_published(self, epoch_id: int, poster: ReportPoster) -> dict[str, Any]:
        """Post frozen bytes, then mark published after an accepted response.

        The persisted body is hashed and compared with its frozen digest while
        the ledger lock is held. The network call occurs only after that check
        and before ``mark_published`` opens its short database transaction.
        """
        with self._lock:
            row = self._epoch(self._connection, epoch_id)
            if (
                row["status"] not in {"complete", "published"}
                or row["report_body"] is None
                or row["report_digest"] is None
            ):
                raise LedgerError(f"epoch {epoch_id} has no publishable report")
            body = bytes(row["report_body"])
            digest = hashlib.sha256(body).hexdigest()
            if digest != str(row["report_digest"]):
                raise LedgerError("persisted report bytes do not match their frozen digest")
        acknowledgement = poster.post(body)
        if acknowledgement.get("status") != "accepted":
            raise LedgerError("publication acknowledgement status must be 'accepted'")
        self.mark_published(epoch_id, digest)
        return acknowledgement

    def get_epoch(self, epoch_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            return dict(row) if row else None

    def receipt_for_challenge(self, challenge_id: str) -> Mapping[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT receipt_id, epoch_id, hotkey, challenge_id, work_status, "
                "receipt_body, receipt_digest, issued_at FROM assurance_receipts "
                "WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        return MappingProxyType(dict(row)) if row is not None else None

    def score_class_snapshot(self, epoch_id: int) -> Mapping[str, Any]:
        """Return frozen score facts and their exact receipt provenance.

        This is the narrow integration boundary used by external Bittensor
        validators.  It deliberately exposes facts, not weights: the consuming
        validator still chooses the metric, class allocation, coldkey collapse,
        and final on-chain vector.

        A positive work row without the atomically stored assurance receipt is
        rejected here so no exporter can accidentally turn legacy, receiptless
        work into a provenance-bearing score-class report.
        """

        with self._lock:
            epoch = self._epoch(self._connection, epoch_id)
            if epoch["status"] not in {"complete", "published"}:
                raise LedgerError(
                    f"epoch {epoch_id} is {epoch['status']}; score facts are not frozen"
                )
            if epoch["report_body"] is None or epoch["report_digest"] is None:
                raise LedgerError(f"epoch {epoch_id} has no completed report")
            report_body = bytes(epoch["report_body"])
            if hashlib.sha256(report_body).hexdigest() != str(epoch["report_digest"]):
                raise LedgerError("persisted report bytes do not match their frozen digest")
            try:
                report = json.loads(report_body)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
                raise LedgerError("persisted report body is invalid") from exc
            if not isinstance(report, dict) or report.get("complete") is not True:
                raise LedgerError("persisted report is not a complete score snapshot")

            rows = self._connection.execute(
                "SELECT scores.hotkey,scores.work_units,scores.score,"
                "receipts.receipt_id,receipts.challenge_id,receipts.work_status,"
                "receipts.receipt_body,receipts.receipt_digest,receipts.issued_at "
                "FROM epoch_scores AS scores LEFT JOIN assurance_receipts AS receipts "
                "ON receipts.epoch_id=scores.epoch_id AND receipts.hotkey=scores.hotkey "
                "WHERE scores.epoch_id = ? ORDER BY scores.hotkey",
                (epoch_id,),
            ).fetchall()
            for row in rows:
                if float(row["work_units"]) > 0 and row["receipt_id"] is None:
                    raise LedgerError(
                        f"positive work for {row['hotkey']!r} lacks an assurance receipt"
                    )
            snapshot = {
                "epoch_id": epoch_id,
                "source_epoch": int(epoch["source_epoch"]),
                "status": str(epoch["status"]),
                "generated_at": str(epoch["generated_at"]),
                "network": report.get("network"),
                "netuid": report.get("netuid"),
                "policy_registry_release": epoch["policy_registry_release"],
                "policy_registry_digest": epoch["policy_registry_digest"],
                "report_digest": "sha256:" + str(epoch["report_digest"]),
                "rows": tuple(MappingProxyType(dict(row)) for row in rows),
            }
        return MappingProxyType(snapshot)

    def get_score_class_export(
        self,
        epoch_id: int,
        *,
        network: str,
        netuid: int,
        class_id: str,
        source_id: str,
    ) -> Mapping[str, Any] | None:
        """Return the immutable first export for one epoch and target class."""

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM score_class_exports WHERE epoch_id = ? AND network = ? "
                "AND netuid = ? AND class_id = ? AND source_id = ?",
                (epoch_id, network, netuid, class_id, source_id),
            ).fetchone()
        return MappingProxyType(dict(row)) if row is not None else None

    def previous_score_class_export(
        self,
        source_epoch: int,
        *,
        network: str,
        netuid: int,
        class_id: str,
        source_id: str,
    ) -> Mapping[str, Any] | None:
        """Return the latest prior export in the same validator-facing stream."""

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM score_class_exports WHERE source_epoch < ? "
                "AND network = ? AND netuid = ? AND class_id = ? AND source_id = ? "
                "ORDER BY source_epoch DESC LIMIT 1",
                (source_epoch, network, netuid, class_id, source_id),
            ).fetchone()
        return MappingProxyType(dict(row)) if row is not None else None

    def record_score_class_export(
        self,
        epoch_id: int,
        *,
        source_epoch: int,
        network: str,
        netuid: int,
        class_id: str,
        source_id: str,
        report_id: str,
        previous_report_id: str | None,
        report_body: bytes,
    ) -> bytes:
        """Persist one append-only report while holding the stream write lock.

        The stream predecessor is checked in the same ``BEGIN IMMEDIATE``
        transaction as the insert. Exact retries replay the frozen bytes, while
        conflicting duplicates and non-monotonic appends fail closed.
        """

        if not isinstance(report_body, bytes) or not report_body:
            raise LedgerError("score-class report body must be nonempty bytes")
        if (
            not isinstance(report_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", report_id) is None
        ):
            raise LedgerError("score-class report id is invalid")
        if previous_report_id is not None and (
            not isinstance(previous_report_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", previous_report_id) is None
        ):
            raise LedgerError("score-class previous report id is invalid")
        try:
            document = json.loads(report_body, object_pairs_hook=_strict_json_object_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise LedgerError("score-class report body is invalid") from exc
        if not isinstance(document, dict) or _canonical_json(document) != report_body:
            raise LedgerError("score-class report body is not canonical JSON")
        if (
            document.get("source_epoch") != source_epoch
            or document.get("network") != network
            or document.get("netuid") != netuid
            or document.get("class_id") != class_id
            or document.get("source_id") != source_id
            or document.get("report_id") != report_id
            or document.get("previous_report_id") != previous_report_id
        ):
            raise LedgerError("score-class report body does not match export metadata")
        report_digest = "sha256:" + hashlib.sha256(report_body).hexdigest()
        with self._transaction() as cx:
            epoch = self._epoch(cx, epoch_id)
            if epoch["status"] not in {"complete", "published"}:
                raise LedgerError(
                    f"epoch {epoch_id} is {epoch['status']}; score facts are not frozen"
                )
            if int(epoch["source_epoch"]) != source_epoch:
                raise LedgerError("score-class source epoch does not match ledger epoch")
            existing = cx.execute(
                "SELECT report_id,report_body FROM score_class_exports WHERE epoch_id = ? "
                "AND network = ? AND netuid = ? AND class_id = ? AND source_id = ?",
                (epoch_id, network, netuid, class_id, source_id),
            ).fetchone()
            if existing is not None:
                frozen = bytes(existing["report_body"])
                if existing["report_id"] == report_id and frozen == report_body:
                    return frozen
                raise LedgerError("conflicting duplicate score-class export")
            latest = cx.execute(
                "SELECT source_epoch,report_id FROM score_class_exports "
                "WHERE network = ? AND netuid = ? AND class_id = ? AND source_id = ? "
                "ORDER BY source_epoch DESC LIMIT 1",
                (network, netuid, class_id, source_id),
            ).fetchone()
            if latest is None:
                if previous_report_id is not None:
                    raise LedgerError(
                        "first score-class export must not declare a previous report id"
                    )
            else:
                if source_epoch <= int(latest["source_epoch"]):
                    raise LedgerError("score-class source epoch is stale or out of order")
                if previous_report_id != str(latest["report_id"]):
                    raise LedgerError("durable export chain changed before insert")
            try:
                cx.execute(
                    "INSERT INTO score_class_exports("
                    "epoch_id,source_epoch,network,netuid,class_id,source_id,"
                    "report_id,report_body,report_digest,created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        epoch_id,
                        source_epoch,
                        network,
                        netuid,
                        class_id,
                        source_id,
                        report_id,
                        report_body,
                        report_digest,
                        _now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise LedgerError("score-class export stream conflicts") from exc
        return report_body

    def attested_hotkeys(self, epoch_id: int) -> frozenset[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT hotkey FROM epoch_attestations WHERE epoch_id = ?", (epoch_id,)
            ).fetchall()
            return frozenset(row["hotkey"] for row in rows)

    def _load_scores(self, cx: sqlite3.Connection, epoch_id: int) -> dict[str, float]:
        rows = cx.execute(
            "SELECT hotkey, score FROM epoch_scores WHERE epoch_id = ? ORDER BY hotkey",
            (epoch_id,),
        ).fetchall()
        return {row["hotkey"]: float(row["score"]) for row in rows}

    @staticmethod
    def _epoch(cx: sqlite3.Connection, epoch_id: int) -> sqlite3.Row:
        row = cx.execute("SELECT * FROM epochs WHERE epoch_id = ?", (epoch_id,)).fetchone()
        if row is None:
            raise LedgerError(f"epoch {epoch_id} not found")
        return row

    def _require_running(self, cx: sqlite3.Connection, epoch_id: int, action: str) -> None:
        row = self._epoch(cx, epoch_id)
        if row["status"] != "running":
            raise LedgerError(f"epoch {epoch_id} is {row['status']}; cannot {action}")

    class _Transaction:
        def __init__(self, ledger: Ledger) -> None:
            self.ledger = ledger

        def __enter__(self) -> sqlite3.Connection:
            self.ledger._lock.acquire()
            if self.ledger._closed:
                self.ledger._lock.release()
                raise LedgerError("ledger is closed")
            self.ledger._connection.execute("BEGIN IMMEDIATE")
            return self.ledger._connection

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            try:
                self.ledger._connection.execute("ROLLBACK" if exc_type else "COMMIT")
            finally:
                self.ledger._lock.release()

    def _transaction(self) -> _Transaction:
        return self._Transaction(self)
