"""Durable confidential-compute epoch ledger."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol


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
    "CREATE UNIQUE INDEX IF NOT EXISTS one_running_epoch "
    "ON epochs ((1)) WHERE status = 'running'"
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
    tee_type TEXT NOT NULL CHECK (tee_type = 'TDX'),
    workload TEXT NOT NULL CHECK (workload = 'CPU'),
    evidence_digest TEXT NOT NULL,
    policy_mode TEXT NOT NULL DEFAULT 'compatibility'
        CHECK (policy_mode IN ('strict', 'compatibility')),
    attested_at TEXT NOT NULL,
    PRIMARY KEY (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS epoch_scores (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey TEXT NOT NULL,
    work_units REAL NOT NULL CHECK (work_units >= 0),
    score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
    PRIMARY KEY (epoch_id, hotkey)
);
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

    def _migrate_registry_policy_fields_if_needed(self) -> None:
        columns = {
            row["name"] for row in self._connection.execute("PRAGMA table_info(epochs)")
        }
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
            row["name"]
            for row in self._connection.execute("PRAGMA table_info(epoch_attestations)")
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
        permanently referencing ``epochs_pre_abandon_migration`` in their
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
            row["name"]
            for row in cx.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
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
        for child_table in ("challenges", "epoch_attestations", "epoch_scores"):
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
    ) -> None:
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
        if status != "verified":
            units = 0.0

        with self._transaction() as cx:
            row = cx.execute(
                "SELECT c.status, c.epoch_id, e.status AS epoch_status "
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
    ) -> None:
        """Add exact VERIFIED TDX CPU evidence to a running epoch."""
        if (verdict, tee_type, workload) != ("VERIFIED", "TDX", "CPU"):
            raise LedgerError("attestation must be exact VERIFIED TDX CPU evidence")
        if not hotkey or not evidence_digest:
            raise LedgerError("hotkey and evidence_digest are required")
        if policy_mode not in {"strict", "compatibility"}:
            raise LedgerError("attestation policy_mode must be strict or compatibility")
        with self._transaction() as cx:
            self._require_running(cx, epoch_id, "add attestations")
            existing = cx.execute(
                "SELECT evidence_digest, policy_mode FROM epoch_attestations "
                "WHERE epoch_id = ? AND hotkey = ?",
                (epoch_id, hotkey),
            ).fetchone()
            if existing:
                if (
                    existing["evidence_digest"] != evidence_digest
                    or existing["policy_mode"] != policy_mode
                ):
                    raise LedgerError("attestation evidence is immutable within an epoch")
                return
            cx.execute(
                "INSERT INTO epoch_attestations "
                "(epoch_id, hotkey, verdict, tee_type, workload, evidence_digest, "
                "policy_mode, attested_at) "
                "VALUES (?, ?, 'VERIFIED', 'TDX', 'CPU', ?, ?, ?)",
                (epoch_id, hotkey, evidence_digest, policy_mode, _now()),
            )

    def complete_epoch(
        self,
        epoch_id: int,
        all_hotkeys: Iterable[str],
        *,
        generated_at: str | None = None,
    ) -> dict[str, float]:
        """Freeze scores and canonical report bytes in one durable transaction."""
        stable_generated_at = _validated_generated_at(generated_at)
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
            if previous_ids:
                placeholders = ",".join("?" for _ in previous_ids)
                for row in cx.execute(
                    f"SELECT hotkey, SUM(work_units) AS total FROM epoch_scores "
                    f"WHERE epoch_id IN ({placeholders}) GROUP BY hotkey",
                    previous_ids,
                ):
                    totals[row["hotkey"]] = totals.get(row["hotkey"], 0.0) + float(row["total"])

            attested = {
                row["hotkey"]
                for row in cx.execute(
                    "SELECT hotkey FROM epoch_attestations WHERE epoch_id = ?", (epoch_id,)
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
            gated = {hotkey: units if hotkey in attested else 0.0 for hotkey, units in totals.items()}
            current_gated = {
                hotkey: units if hotkey in attested else 0.0
                for hotkey, units in current_work.items()
            }
            maximum = max(gated.values(), default=0.0)
            scores = {
                hotkey: (units / maximum if maximum > 0 else 0.0)
                for hotkey, units in gated.items()
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
                },
                "scores": [
                    {"miner_hotkey": hotkey, "score": scores[hotkey]}
                    for hotkey in sorted(scores)
                ],
                "source": "cathedral_confidential_tdx",
            }
            body = _canonical_json(report)
            digest = hashlib.sha256(body).hexdigest()
            completed_at = _now()
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

    def post_and_mark_published(
        self, epoch_id: int, poster: ReportPoster
    ) -> dict[str, Any]:
        """Post frozen bytes, then mark published after an accepted response.

        The network call occurs after ``report_bytes`` releases the ledger lock
        and before ``mark_published`` opens its short database transaction.
        """
        body = self.report_bytes(epoch_id)
        acknowledgement = poster.post(body)
        if acknowledgement.get("status") != "accepted":
            raise LedgerError("publication acknowledgement status must be 'accepted'")
        self.mark_published(epoch_id, hashlib.sha256(body).hexdigest())
        return acknowledgement

    def get_epoch(self, epoch_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            return dict(row) if row else None

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
