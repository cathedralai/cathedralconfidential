"""Challenge and epoch ledger backed by SQLite.

Tracks the full lifecycle of attestation challenges (issued → verified /
failed / abandoned) and validator epochs (running → complete / aborted →
published). Computes gated window scores for weight-setting.

Scoring model (docs/DESIGN.md §5, §6)
--------------------------------------
Window  : sum verifier-derived work_units per hotkey across the last N
          complete/published epochs.
Gate    : a hotkey must hold a TDX attestation row in the *current* epoch to
          receive any weight; absent hotkeys score 0 and are excluded.
Revoke  : ``complete_epoch`` accepts the full hotkey universe; any hotkey
          absent or zero-scoring is explicitly recorded at 0.0 so the window
          never silently carries stale positive scores.

Abort / failure rules
---------------------
* An aborted epoch cannot be completed or published.
* source_epoch is UNIQUE — the monotonic external epoch counter cannot be
  reused, enforcing advance-on-complete-only semantics.
* A healthy epoch with no challenges still completes (all hotkeys revoked,
  weights all-zero) and is publishable.

Idempotency
-----------
* ``issue_challenge`` is NOT idempotent — duplicate challenge_id raises.
* ``add_attestation`` is idempotent (UNIQUE ON CONFLICT REPLACE).
* ``complete_epoch`` is idempotent when the epoch is already 'complete';
  returns the stored scores without modification.
* ``mark_published`` is idempotent when the digest matches the stored one.
"""
from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS epochs (
    epoch_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    status       TEXT    NOT NULL DEFAULT 'running',
    source_epoch INTEGER NOT NULL UNIQUE,
    report_digest TEXT,
    started_at   TEXT    NOT NULL,
    completed_at TEXT,
    published_at TEXT
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT    PRIMARY KEY,
    hotkey       TEXT    NOT NULL,
    epoch_id     INTEGER NOT NULL REFERENCES epochs(epoch_id),
    status       TEXT    NOT NULL DEFAULT 'issued',
    work_units   REAL    NOT NULL DEFAULT 0.0,
    issued_at    TEXT    NOT NULL,
    resolved_at  TEXT
);

CREATE TABLE IF NOT EXISTS epoch_attestations (
    epoch_id     INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey       TEXT    NOT NULL,
    chip_id      TEXT    NOT NULL,
    measurement  TEXT    NOT NULL,
    tcb          INTEGER NOT NULL,
    attested_at  TEXT    NOT NULL,
    PRIMARY KEY (epoch_id, hotkey)
);

CREATE TABLE IF NOT EXISTS epoch_scores (
    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
    hotkey   TEXT    NOT NULL,
    score    REAL    NOT NULL DEFAULT 0.0,
    PRIMARY KEY (epoch_id, hotkey)
);
"""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LedgerError(Exception):
    """Raised on illegal state transitions or constraint violations."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Ledger:
    """SQLite-backed challenge and epoch ledger.

    Pass ``db_path=':memory:'`` (default) for in-process tests; pass a real
    file path for persistence across restarts.

    Thread-safety: each public method opens and closes its own connection;
    callers sharing a ``Ledger`` across threads should serialize externally.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        if db_path == ":memory:":
            # Use unique URI for each in-memory instance to avoid cross-contamination
            self._path = f"file:ledger_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._is_memory = True
        else:
            self._path = db_path
            self._is_memory = False
        self._persistent_conn = None  # For in-memory DB, keep one connection alive
        
        # Create initial schema
        with self._conn() as cx:
            cx.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # For in-memory DBs, use URI with shared cache and keep one connection persistent
        if self._is_memory:
            if self._persistent_conn is None:
                self._persistent_conn = sqlite3.connect(self._path, uri=True, check_same_thread=False)
                self._persistent_conn.row_factory = sqlite3.Row
                self._persistent_conn.execute("PRAGMA journal_mode=DELETE")  # WAL has issues with in-memory
                self._persistent_conn.execute("PRAGMA foreign_keys=ON")
            cx = self._persistent_conn
        else:
            cx = sqlite3.connect(self._path, check_same_thread=False)
            cx.row_factory = sqlite3.Row
            cx.execute("PRAGMA journal_mode=WAL")
            cx.execute("PRAGMA foreign_keys=ON")
        try:
            yield cx
        finally:
            # Don't close persistent in-memory connection
            if not self._is_memory:
                cx.close()

    # ------------------------------------------------------------------
    # Challenges
    # ------------------------------------------------------------------

    def issue_challenge(
        self, challenge_id: str, hotkey: str, epoch_id: int
    ) -> None:
        """Record a new challenge in an open epoch.

        Raises :class:`LedgerError` on duplicate challenge_id or if the epoch
        is not in 'running' state.
        """
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"epoch {epoch_id} not found")
            if row["status"] != "running":
                raise LedgerError(
                    f"epoch {epoch_id} is '{row['status']}'; cannot issue challenges"
                )
            try:
                cx.execute(
                    """
                    INSERT INTO challenges
                        (challenge_id, hotkey, epoch_id, status, work_units, issued_at)
                    VALUES (?, ?, ?, 'issued', 0.0, ?)
                    """,
                    (challenge_id, hotkey, epoch_id, _now()),
                )
                cx.commit()
            except sqlite3.IntegrityError as exc:
                raise LedgerError(
                    f"duplicate challenge_id {challenge_id!r}"
                ) from exc

    def resolve_challenge(
        self,
        challenge_id: str,
        status: str,
        work_units: float = 0.0,
    ) -> None:
        """Transition a challenge from 'issued' to verified / failed / abandoned.

        ``work_units`` is the verifier-derived credit; only meaningful for
        'verified'; set 0.0 for failed/abandoned.
        """
        if status not in ("verified", "failed", "abandoned"):
            raise LedgerError(f"invalid resolve status: {status!r}")
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status FROM challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            if row is None:
                raise LedgerError(f"challenge {challenge_id!r} not found")
            if row["status"] != "issued":
                raise LedgerError(
                    f"challenge {challenge_id!r} is already '{row['status']}'"
                )
            cx.execute(
                """
                UPDATE challenges
                   SET status = ?, work_units = ?, resolved_at = ?
                 WHERE challenge_id = ?
                """,
                (status, work_units, _now(), challenge_id),
            )
            cx.commit()

    # ------------------------------------------------------------------
    # Epochs
    # ------------------------------------------------------------------

    def begin_epoch(self, source_epoch: int) -> int:
        """Open a new epoch.  Returns the internal epoch_id.

        ``source_epoch`` must be strictly greater than all existing
        source_epochs (monotonically increasing external counter).
        """
        with self._conn() as cx:
            max_row = cx.execute(
                "SELECT MAX(source_epoch) AS m FROM epochs"
            ).fetchone()
            if max_row["m"] is not None and source_epoch <= max_row["m"]:
                raise LedgerError(
                    f"source_epoch {source_epoch} is not greater than "
                    f"existing maximum {max_row['m']}"
                )
            cur = cx.execute(
                "INSERT INTO epochs (status, source_epoch, started_at) VALUES ('running', ?, ?)",
                (source_epoch, _now()),
            )
            cx.commit()
            return cur.lastrowid  # type: ignore[return-value]

    def add_attestation(
        self,
        epoch_id: int,
        hotkey: str,
        chip_id: str,
        measurement: str,
        tcb: int,
    ) -> None:
        """Record a TDX attestation row for a hotkey in an epoch.

        Idempotent: a second call for the same (epoch_id, hotkey) overwrites
        the prior row (chip_id / measurement / tcb may be updated on refresh).
        Permitted for 'running' and 'complete' epochs.
        """
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"epoch {epoch_id} not found")
            if row["status"] not in ("running", "complete"):
                raise LedgerError(
                    f"cannot add attestation to epoch in status '{row['status']}'"
                )
            cx.execute(
                """
                INSERT INTO epoch_attestations
                    (epoch_id, hotkey, chip_id, measurement, tcb, attested_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(epoch_id, hotkey) DO UPDATE SET
                    chip_id     = excluded.chip_id,
                    measurement = excluded.measurement,
                    tcb         = excluded.tcb,
                    attested_at = excluded.attested_at
                """,
                (epoch_id, hotkey, chip_id, measurement, tcb, _now()),
            )
            cx.commit()

    def complete_epoch(
        self,
        epoch_id: int,
        all_hotkeys: frozenset[str] | set[str],
    ) -> dict[str, float]:
        """Atomically snapshot the epoch and transition it to 'complete'.

        Computes per-hotkey scores from verified challenges, then records
        explicit 0.0 for every hotkey in ``all_hotkeys`` that is absent or
        zero-scoring (omission/zero revoke).

        Returns the full ``{hotkey: score}`` map including revoked zeros.

        Idempotent: if the epoch is already 'complete' or 'published', returns
        the stored scores without modification.

        Raises :class:`LedgerError` if the epoch is 'aborted' or unknown.
        """
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"epoch {epoch_id} not found")

            # Idempotent read-back for already-completed epochs
            if row["status"] in ("complete", "published"):
                return self._load_epoch_scores(cx, epoch_id)

            if row["status"] != "running":
                raise LedgerError(
                    f"epoch {epoch_id} is '{row['status']}'; cannot complete"
                )

            # Compute per-hotkey score from verified challenges
            rows = cx.execute(
                """
                SELECT hotkey, SUM(work_units) AS total
                  FROM challenges
                 WHERE epoch_id = ? AND status = 'verified'
                 GROUP BY hotkey
                """,
                (epoch_id,),
            ).fetchall()
            scores: dict[str, float] = {r["hotkey"]: float(r["total"]) for r in rows}

            # Explicit zero for every registered hotkey not already scoring
            for hk in all_hotkeys:
                scores.setdefault(hk, 0.0)

            # Single atomic commit
            now = _now()
            cx.execute(
                "UPDATE epochs SET status='complete', completed_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
            for hk, sc in scores.items():
                cx.execute(
                    """
                    INSERT INTO epoch_scores (epoch_id, hotkey, score)
                    VALUES (?, ?, ?)
                    ON CONFLICT(epoch_id, hotkey) DO UPDATE SET score = excluded.score
                    """,
                    (epoch_id, hk, sc),
                )
            cx.commit()
            return dict(scores)

    def abort_epoch(self, epoch_id: int) -> None:
        """Mark epoch as 'aborted'.  No-op if already aborted.

        An aborted epoch can never be completed or published; its source_epoch
        slot is consumed, preventing reuse.
        """
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"epoch {epoch_id} not found")
            if row["status"] == "aborted":
                return  # no-op
            if row["status"] in ("complete", "published"):
                raise LedgerError(
                    f"epoch {epoch_id} is '{row['status']}'; cannot abort"
                )
            cx.execute(
                "UPDATE epochs SET status='aborted' WHERE epoch_id=?", (epoch_id,)
            )
            cx.commit()

    def mark_published(self, epoch_id: int, report_digest: str) -> None:
        """Transition a complete epoch to 'published', recording the digest.

        Idempotent: if already published with the *same* digest, no-op.
        Raises if the epoch is not 'complete', or if the digest differs from
        a prior publish (mismatched retry).
        """
        with self._conn() as cx:
            row = cx.execute(
                "SELECT status, report_digest FROM epochs WHERE epoch_id = ?",
                (epoch_id,),
            ).fetchone()
            if row is None:
                raise LedgerError(f"epoch {epoch_id} not found")
            if row["status"] == "published":
                if row["report_digest"] != report_digest:
                    raise LedgerError(
                        f"epoch {epoch_id} already published with a different digest"
                    )
                return  # idempotent
            if row["status"] != "complete":
                raise LedgerError(
                    f"epoch {epoch_id} is '{row['status']}'; cannot publish"
                )
            cx.execute(
                """
                UPDATE epochs
                   SET status='published', report_digest=?, published_at=?
                 WHERE epoch_id=?
                """,
                (report_digest, _now(), epoch_id),
            )
            cx.commit()

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def window_scores(self, *, n: int = 3) -> dict[str, float]:
        """Sum epoch_scores per hotkey across the last *n* complete/published epochs.

        Epochs are ordered by source_epoch descending; partial windows
        (fewer than *n* complete epochs) are valid — we sum what exists.
        Returns an empty dict if no complete epochs exist.
        """
        with self._conn() as cx:
            epoch_ids = [
                r["epoch_id"]
                for r in cx.execute(
                    """
                    SELECT epoch_id FROM epochs
                     WHERE status IN ('complete', 'published')
                     ORDER BY source_epoch DESC
                     LIMIT ?
                    """,
                    (n,),
                ).fetchall()
            ]
            if not epoch_ids:
                return {}
            placeholders = ",".join("?" * len(epoch_ids))
            rows = cx.execute(
                f"""
                SELECT hotkey, SUM(score) AS total
                  FROM epoch_scores
                 WHERE epoch_id IN ({placeholders})
                 GROUP BY hotkey
                """,
                epoch_ids,
            ).fetchall()
            return {r["hotkey"]: float(r["total"]) for r in rows}

    def attested_hotkeys(self, epoch_id: int) -> frozenset[str]:
        """Return the set of hotkeys with a TDX attestation row in *epoch_id*."""
        with self._conn() as cx:
            rows = cx.execute(
                "SELECT hotkey FROM epoch_attestations WHERE epoch_id = ?",
                (epoch_id,),
            ).fetchall()
            return frozenset(r["hotkey"] for r in rows)

    def gated_scores(self, epoch_id: int, *, n: int = 3) -> dict[str, float]:
        """Window scores filtered by fresh attestation in *epoch_id*.

        Only hotkeys with an attestation row in *epoch_id* AND a positive
        window score are returned.  Others receive zero (not included).
        """
        scores = self.window_scores(n=n)
        attested = self.attested_hotkeys(epoch_id)
        return {hk: sc for hk, sc in scores.items() if hk in attested and sc > 0.0}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_epoch(self, epoch_id: int) -> dict | None:
        """Return epoch metadata as a plain dict, or None if not found."""
        with self._conn() as cx:
            row = cx.execute(
                "SELECT * FROM epochs WHERE epoch_id = ?", (epoch_id,)
            ).fetchone()
            return dict(row) if row else None

    def _load_epoch_scores(
        self, cx: sqlite3.Connection, epoch_id: int
    ) -> dict[str, float]:
        rows = cx.execute(
            "SELECT hotkey, score FROM epoch_scores WHERE epoch_id = ?",
            (epoch_id,),
        ).fetchall()
        return {r["hotkey"]: float(r["score"]) for r in rows}
