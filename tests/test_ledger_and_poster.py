from __future__ import annotations

import hashlib
import hmac
import json
import socket
import sqlite3
import threading
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from cathedral.ledger import _EPOCHS_MIGRATION_TEMP_PREFIX, Ledger, LedgerError
from cathedral.poster import Poster, PosterError


GPU_AUTHORITY = (
    "gpu-profile:tdx-h100-v1@profile=sha256:" + "a" * 64 + "@release=7@registry=sha256:" + "b" * 64
)
GPU_AUTHORITY_CHANGED = (
    "gpu-profile:tdx-h100-v1@profile=sha256:" + "c" * 64 + "@release=8@registry=sha256:" + "d" * 64
)


def attest(
    ledger: Ledger, epoch_id: int, hotkey: str, *, policy_mode: str = "compatibility"
) -> None:
    ledger.add_attestation(
        epoch_id,
        hotkey,
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest=f"evidence-{hotkey}",
        policy_mode=policy_mode,
    )


def verified_work(
    ledger: Ledger, epoch_id: int, challenge_id: str, hotkey: str, units: float
) -> None:
    ledger.issue_challenge(challenge_id, hotkey, epoch_id)
    ledger.resolve_challenge(challenge_id, "verified", units, validator_derived=True)


def complete_and_publish(
    ledger: Ledger,
    source_epoch: int,
    work: dict[str, float],
    hotkeys: set[str],
) -> int:
    epoch_id = ledger.begin_epoch(source_epoch)
    for index, (hotkey, units) in enumerate(work.items()):
        verified_work(ledger, epoch_id, f"{source_epoch}-{index}", hotkey, units)
    for hotkey in hotkeys:
        attest(ledger, epoch_id, hotkey)
    ledger.complete_epoch(epoch_id, hotkeys, generated_at=f"2026-01-{source_epoch:02d}T00:00:00Z")
    ledger.mark_published(epoch_id)
    return epoch_id


def report(ledger: Ledger, epoch_id: int) -> dict:
    return json.loads(ledger.report_bytes(epoch_id))


def scores_by_hotkey(payload: dict) -> dict[str, float]:
    return {row["miner_hotkey"]: row["score"] for row in payload["scores"]}


class TestEpochStateMachine:
    def test_memory_ledger_persists_for_lifetime(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        assert ledger.get_epoch(epoch_id)["status"] == "running"
        ledger.complete_epoch(epoch_id, {"hk"})
        assert scores_by_hotkey(report(ledger, epoch_id)) == {"hk": 0.0}

    def test_thread_safe_single_running_epoch(self) -> None:
        ledger = Ledger()
        barrier = threading.Barrier(3)
        outcomes: list[object] = []

        def begin(source_epoch: int) -> None:
            barrier.wait()
            try:
                outcomes.append(ledger.begin_epoch(source_epoch))
            except LedgerError as exc:
                outcomes.append(exc)

        threads = [threading.Thread(target=begin, args=(value,)) for value in (1, 2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        assert sum(isinstance(value, int) for value in outcomes) == 1
        assert sum(isinstance(value, LedgerError) for value in outcomes) == 1

    def test_abort_does_not_consume_source_epoch(self) -> None:
        ledger = Ledger()
        first = ledger.begin_epoch(10)
        ledger.abort_epoch(first)
        with pytest.raises(LedgerError, match="must be retried"):
            ledger.begin_epoch(11)
        retry = ledger.begin_epoch(10)
        assert retry != first
        ledger.complete_epoch(retry, set())
        ledger.mark_published(retry)
        assert ledger.begin_epoch(11)

    def test_completed_snapshot_must_publish_before_next_epoch(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)
        ledger.mark_published(epoch_id)
        assert ledger.begin_epoch(2)

    def test_source_epoch_finalized_uniqueness_and_monotonicity(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(4)
        ledger.complete_epoch(epoch_id, set())
        ledger.mark_published(epoch_id)
        with pytest.raises(LedgerError, match="greater than finalized"):
            ledger.begin_epoch(4)

    def test_crash_reopen_preserves_frozen_report(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.sqlite3"
        first = Ledger(path)
        epoch_id = first.begin_epoch(1)
        verified_work(first, epoch_id, "challenge", "hk", 7)
        attest(first, epoch_id, "hk")
        first.complete_epoch(epoch_id, {"hk"}, generated_at="2026-01-01T00:00:00Z")
        body = first.report_bytes(epoch_id)
        digest = first.report_digest(epoch_id)
        first.close()

        reopened = Ledger(path)
        assert reopened.report_bytes(epoch_id) == body
        assert reopened.report_digest(epoch_id) == digest
        reopened.mark_published(epoch_id, digest)
        assert reopened.get_epoch(epoch_id)["status"] == "published"

    def test_reopen_exposes_immutable_blocking_epoch(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.sqlite3"
        first = Ledger(path)
        epoch_id = first.begin_epoch(12)
        first.close()

        reopened = Ledger(path)
        blocking = reopened.blocking_epoch()
        assert blocking is not None
        assert blocking["epoch_id"] == epoch_id
        assert blocking["source_epoch"] == 12
        assert blocking["status"] == "running"
        assert reopened.pending_epoch() == blocking
        with pytest.raises(TypeError):
            blocking["status"] = "published"  # type: ignore[index]

        reopened.complete_epoch(epoch_id, set())
        assert reopened.blocking_epoch()["status"] == "complete"
        reopened.mark_published(epoch_id)
        assert reopened.blocking_epoch() is None


class TestEvidenceAndResolution:
    @pytest.mark.parametrize(
        ("verdict", "tee_type", "workload"),
        [
            ("verified", "TDX", "CPU"),
            ("VERIFIED", "SNP", "CPU"),
            ("VERIFIED", "TDX", "GPU"),
        ],
    )
    def test_only_exact_verified_supported_hardware_shapes(
        self, verdict: str, tee_type: str, workload: str
    ) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        with pytest.raises(LedgerError, match="hardware shape"):
            ledger.add_attestation(
                epoch_id,
                "hk",
                verdict=verdict,
                tee_type=tee_type,
                workload=workload,
                evidence_digest="digest",
            )

    def test_composite_gpu_attestation_shape_and_profile_are_persisted(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.add_attestation(
            epoch_id,
            "gpu-hotkey",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="composite-evidence",
            policy_mode=GPU_AUTHORITY,
            score_eligible=True,
        )
        ledger.complete_epoch(epoch_id, {"gpu-hotkey"})

        assert report(ledger, epoch_id)["metadata"]["attestation_policy_modes"] == [GPU_AUTHORITY]

    def test_cpu_only_attestation_schema_migrates_without_losing_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "gpu-migration.sqlite"
        initial = Ledger(path)
        epoch_id = initial.begin_epoch(1)
        attest(initial, epoch_id, "cpu-hotkey", policy_mode="strict")
        initial.close()

        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("ALTER TABLE epoch_attestations RENAME TO attestations_current")
            connection.execute(
                "CREATE TABLE epoch_attestations ("
                "epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),"
                "hotkey TEXT NOT NULL,"
                "verdict TEXT NOT NULL CHECK (verdict='VERIFIED'),"
                "tee_type TEXT NOT NULL CHECK (tee_type='TDX'),"
                "workload TEXT NOT NULL CHECK (workload='CPU'),"
                "evidence_digest TEXT NOT NULL,"
                "policy_mode TEXT NOT NULL DEFAULT 'compatibility',"
                "attested_at TEXT NOT NULL,"
                "PRIMARY KEY (epoch_id,hotkey))"
            )
            connection.execute(
                "INSERT INTO epoch_attestations "
                "SELECT epoch_id,hotkey,verdict,tee_type,workload,evidence_digest,"
                "policy_mode,attested_at FROM attestations_current"
            )
            connection.execute("DROP TABLE attestations_current")

        migrated = Ledger(path)
        rows = migrated._connection.execute(
            "SELECT hotkey,tee_type,workload,policy_mode FROM epoch_attestations "
            "WHERE epoch_id=? ORDER BY hotkey",
            (epoch_id,),
        ).fetchall()
        assert [tuple(row) for row in rows] == [("cpu-hotkey", "TDX", "CPU", "strict")]
        migrated.add_attestation(
            epoch_id,
            "gpu-hotkey",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="gpu-evidence",
            policy_mode=GPU_AUTHORITY,
        )
        assert migrated._connection.execute("PRAGMA foreign_key_check").fetchall() == []
        migrated.close()

    def test_attestation_only_while_running_and_is_immutable(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        attest(ledger, epoch_id, "hk")
        with pytest.raises(LedgerError, match="immutable"):
            ledger.add_attestation(
                epoch_id,
                "hk",
                verdict="VERIFIED",
                tee_type="TDX",
                workload="CPU",
                evidence_digest="changed",
            )
        ledger.complete_epoch(epoch_id, {"hk"})
        with pytest.raises(LedgerError, match="cannot add attestations"):
            attest(ledger, epoch_id, "other")

    def test_attestation_policy_mode_is_immutable_and_visible_in_report(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        attest(ledger, epoch_id, "hk", policy_mode="strict")
        with pytest.raises(LedgerError, match="immutable"):
            ledger.add_attestation(
                epoch_id,
                "hk",
                verdict="VERIFIED",
                tee_type="TDX",
                workload="CPU",
                evidence_digest="evidence-hk",
                policy_mode="compatibility",
            )

        ledger.complete_epoch(epoch_id, {"hk"})

        assert report(ledger, epoch_id)["metadata"]["attestation_policy_modes"] == ["strict"]

    @pytest.mark.parametrize("units", [-1, float("nan"), float("inf"), float("-inf")])
    def test_verified_work_must_be_finite_nonnegative(self, units: float) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="finite and nonnegative"):
            ledger.resolve_challenge("challenge", "verified", units, validator_derived=True)

    def test_verified_work_must_be_validator_derived(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="validator-derived"):
            ledger.resolve_challenge("challenge", "verified", 10)

    @pytest.mark.parametrize("status", ["failed", "abandoned"])
    def test_failed_and_abandoned_force_zero(self, status: str) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        attest(ledger, epoch_id, "hk")
        ledger.issue_challenge("challenge", "hk", epoch_id)
        ledger.resolve_challenge("challenge", status, 999)
        scores = ledger.complete_epoch(epoch_id, {"hk"})
        assert scores == {"hk": 0.0}

    def test_resolve_only_while_running(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        ledger.abort_epoch(epoch_id)
        with pytest.raises(LedgerError, match="only be resolved"):
            ledger.resolve_challenge("challenge", "failed")

    def test_complete_rejects_unresolved_challenges(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="unresolved issued"):
            ledger.complete_epoch(epoch_id, {"hk"})


class TestReportSnapshot:
    @pytest.mark.parametrize("generated_at", ["not-a-date", "2026-01-01T00:00:00"])
    def test_generated_at_must_be_timezone_aware_before_mutation(self, generated_at: str) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        with pytest.raises(LedgerError, match="timezone-aware ISO-8601"):
            ledger.complete_epoch(epoch_id, {"hk"}, generated_at=generated_at)
        assert ledger.get_epoch(epoch_id)["status"] == "running"
        with pytest.raises(LedgerError, match="no completed report"):
            ledger.report_bytes(epoch_id)

    def test_default_generated_at_is_current_utc(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        generated_at = datetime.fromisoformat(report(ledger, epoch_id)["generated_at"])
        assert generated_at.utcoffset() is not None
        assert generated_at.utcoffset().total_seconds() == 0

    def test_full_universe_zero_revocation_fresh_gate_and_max_normalization(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        verified_work(ledger, epoch_id, "a", "leader", 20)
        verified_work(ledger, epoch_id, "b", "half", 10)
        verified_work(ledger, epoch_id, "c", "stale", 50)
        attest(ledger, epoch_id, "leader")
        attest(ledger, epoch_id, "half")
        attest(ledger, epoch_id, "idle")

        scores = ledger.complete_epoch(
            epoch_id,
            {"leader", "half", "stale", "idle", "enrolled"},
            generated_at="2026-01-01T00:00:00Z",
        )
        assert scores == {
            "leader": 1.0,
            "half": 0.5,
            "stale": 0.0,
            "idle": 0.0,
            "enrolled": 0.0,
        }
        assert all(0 <= value <= 1 for value in scores.values())

    def test_only_published_previous_epochs_enter_trailing_window(self) -> None:
        ledger = Ledger(window_size=3)
        complete_and_publish(ledger, 1, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 2, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 3, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 4, {"old": 1000}, {"old", "new"})

        current = ledger.begin_epoch(5)
        verified_work(ledger, current, "current", "new", 300)
        attest(ledger, current, "old")
        attest(ledger, current, "new")
        scores = ledger.complete_epoch(current, {"old", "new"})

        # Epoch 1 fell out; epochs 2-4 plus current are used.
        assert scores == {"old": 1.0, "new": 300 / 1200}
        assert report(ledger, current)["metadata"]["published_window_epochs"] == [2, 3, 4]

    def test_prior_cpu_score_cannot_leak_into_a_gpu_audit_epoch(self) -> None:
        ledger = Ledger(window_size=3)
        complete_and_publish(ledger, 1, {"worker": 100}, {"worker"})

        gpu_epoch = ledger.begin_epoch(2)
        ledger.add_attestation(
            gpu_epoch,
            "worker",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="composite-evidence",
            policy_mode=GPU_AUTHORITY,
        )

        assert ledger.complete_epoch(gpu_epoch, {"worker"}) == {"worker": 0.0}

    def test_changed_signed_gpu_authority_cannot_inherit_prior_gpu_score(self) -> None:
        ledger = Ledger(window_size=3)
        first = ledger.begin_epoch(1)
        verified_work(ledger, first, "gpu-work-1", "worker", 100)
        ledger.add_attestation(
            first,
            "worker",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="gpu-evidence-1",
            policy_mode=GPU_AUTHORITY,
            score_eligible=True,
        )
        ledger.complete_epoch(first, {"worker"})
        ledger.mark_published(first)

        second = ledger.begin_epoch(2)
        ledger.add_attestation(
            second,
            "worker",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="gpu-evidence-2",
            policy_mode=GPU_AUTHORITY_CHANGED,
            score_eligible=True,
        )

        assert ledger.complete_epoch(second, {"worker"}) == {"worker": 0.0}

    def test_expired_gpu_score_authority_cannot_complete_epoch(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        verified_work(ledger, epoch_id, "gpu-work", "worker", 100)
        ledger.add_attestation(
            epoch_id,
            "worker",
            verdict="VERIFIED",
            tee_type="TDX+GPU_CC",
            workload="GPU",
            evidence_digest="gpu-evidence",
            policy_mode=GPU_AUTHORITY,
            score_eligible=True,
        )

        with pytest.raises(LedgerError, match="score authority expired"):
            ledger.complete_epoch(
                epoch_id,
                {"worker"},
                score_authority_valid_until=datetime.now(UTC) - timedelta(seconds=1),
            )

        assert ledger.get_epoch(epoch_id)["status"] == "running"
        with ledger._lock:
            assert (
                ledger._connection.execute(
                    "SELECT COUNT(*) FROM epoch_scores WHERE epoch_id = ?",
                    (epoch_id,),
                ).fetchone()[0]
                == 0
            )

    def test_unpublished_completed_epoch_cannot_leak_into_window(self) -> None:
        ledger = Ledger()
        prior = ledger.begin_epoch(1)
        verified_work(ledger, prior, "prior", "hk", 100)
        attest(ledger, prior, "hk")
        ledger.complete_epoch(prior, {"hk"})
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)

        # An aborted attempt also contributes nothing when the same source epoch is retried.
        ledger.mark_published(prior)
        attempt = ledger.begin_epoch(2)
        verified_work(ledger, attempt, "discarded", "other", 999)
        attest(ledger, attempt, "other")
        ledger.abort_epoch(attempt)
        retry = ledger.begin_epoch(2)
        attest(ledger, retry, "hk")
        attest(ledger, retry, "other")
        scores = ledger.complete_epoch(retry, {"hk", "other"})
        assert scores == {"hk": 1.0, "other": 0.0}

    def test_report_schema_and_exact_byte_idempotency(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(7)
        verified_work(ledger, epoch_id, "challenge", "hk", 3)
        attest(ledger, epoch_id, "hk")
        first_scores = ledger.complete_epoch(epoch_id, {"hk"}, generated_at="2026-01-07T12:00:00Z")
        first_body = ledger.report_bytes(epoch_id)
        first_digest = ledger.report_digest(epoch_id)

        second_scores = ledger.complete_epoch(
            epoch_id, {"hk", "mutating-input"}, generated_at="2099-01-01T00:00:00Z"
        )
        assert second_scores == first_scores
        assert ledger.report_bytes(epoch_id) == first_body
        assert (
            ledger.report_digest(epoch_id) == first_digest == hashlib.sha256(first_body).hexdigest()
        )

        payload = json.loads(first_body)
        assert payload["source"] == payload["mechanism"] == "cathedral_confidential_tdx"
        assert payload["epoch"] == 7
        assert payload["complete"] is True
        assert payload["generated_at"] == "2026-01-07T12:00:00Z"
        assert payload["scores"] == [{"miner_hotkey": "hk", "score": 1.0}]
        assert (
            first_body
            == json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        )

    def test_publish_requires_persisted_digest(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="does not match"):
            ledger.mark_published(epoch_id, "wrong")
        ledger.mark_published(epoch_id, ledger.report_digest(epoch_id))
        ledger.mark_published(epoch_id, ledger.report_digest(epoch_id))


class TestAbandonCompletedEpoch:
    """Audited recovery for a 'complete' epoch that can never publish."""

    def test_abandon_transitions_status_and_records_audit_fields(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        assert ledger.get_epoch(epoch_id)["abandon_reason"] is None

        ledger.abandon_completed_epoch(epoch_id, "report too old for first ingest")
        row = ledger.get_epoch(epoch_id)
        assert row["status"] == "abandoned"
        assert row["abandon_reason"] == "report too old for first ingest"
        assert row["abandoned_at"] is not None

    def test_abandon_strips_reason_whitespace(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        ledger.abandon_completed_epoch(epoch_id, "  stale report  ")
        assert ledger.get_epoch(epoch_id)["abandon_reason"] == "stale report"

    @pytest.mark.parametrize("reason", ["", "   ", None])
    def test_abandon_requires_nonempty_reason(self, reason) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="nonempty"):
            ledger.abandon_completed_epoch(epoch_id, reason)
        assert ledger.get_epoch(epoch_id)["status"] == "complete"

    def test_abandon_does_not_mutate_frozen_report_bytes(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        verified_work(ledger, epoch_id, "challenge", "hk", 5)
        attest(ledger, epoch_id, "hk")
        ledger.complete_epoch(epoch_id, {"hk"}, generated_at="2020-01-01T00:00:00Z")
        body_before = ledger.report_bytes(epoch_id)
        digest_before = ledger.report_digest(epoch_id)

        ledger.abandon_completed_epoch(epoch_id, "too old for first ingest")
        assert ledger.report_bytes(epoch_id) == body_before
        assert ledger.report_digest(epoch_id) == digest_before

    def test_only_a_complete_epoch_can_be_abandoned_running_rejected(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        with pytest.raises(LedgerError, match="running.*cannot|only a complete"):
            ledger.abandon_completed_epoch(epoch_id, "reason")
        assert ledger.get_epoch(epoch_id)["status"] == "running"

    def test_only_a_complete_epoch_can_be_abandoned_aborted_rejected(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.abort_epoch(epoch_id)
        with pytest.raises(LedgerError, match="only a complete"):
            ledger.abandon_completed_epoch(epoch_id, "reason")

    def test_only_a_complete_epoch_can_be_abandoned_published_rejected(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        ledger.mark_published(epoch_id)
        with pytest.raises(LedgerError, match="only a complete"):
            ledger.abandon_completed_epoch(epoch_id, "reason")

    def test_abandoned_epoch_cannot_be_abandoned_again(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        ledger.abandon_completed_epoch(epoch_id, "first reason")
        with pytest.raises(LedgerError, match="only a complete"):
            ledger.abandon_completed_epoch(epoch_id, "second reason")
        assert ledger.get_epoch(epoch_id)["abandon_reason"] == "first reason"

    def test_abandoned_epoch_can_never_be_published(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        ledger.abandon_completed_epoch(epoch_id, "reason")
        with pytest.raises(LedgerError, match="cannot publish"):
            ledger.mark_published(epoch_id)

    def test_abandon_unblocks_begin_epoch(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)
        ledger.abandon_completed_epoch(epoch_id, "reason")
        assert ledger.begin_epoch(2)

    def test_abandoned_epoch_scores_never_enter_the_trailing_window(self) -> None:
        ledger = Ledger(window_size=3)
        epoch_id = ledger.begin_epoch(1)
        verified_work(ledger, epoch_id, "challenge", "hk", 1000)
        attest(ledger, epoch_id, "hk")
        ledger.complete_epoch(epoch_id, {"hk"})
        ledger.abandon_completed_epoch(epoch_id, "too old for first ingest")

        next_epoch = ledger.begin_epoch(2)
        attest(ledger, next_epoch, "hk")
        scores = ledger.complete_epoch(next_epoch, {"hk"})
        # The abandoned epoch's 1000 verified work units contribute nothing:
        # with no other published history, "hk" has zero prior credited work.
        assert scores == {"hk": 0.0}

    def test_abandon_nonexistent_epoch_raises(self) -> None:
        ledger = Ledger()
        with pytest.raises(LedgerError, match="not found"):
            ledger.abandon_completed_epoch(999, "reason")


class TestEpochsTableMigration:
    """A pre-existing on-disk ledger without 'abandoned' support is migrated in place."""

    @staticmethod
    def _create_legacy_schema(path: Path) -> None:
        """Build a ledger file using the schema that predates 'abandoned'."""
        import sqlite3 as _sqlite3

        cx = _sqlite3.connect(str(path))
        try:
            cx.executescript(
                """
                CREATE TABLE epochs (
                    epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_epoch INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('running', 'aborted', 'complete', 'published')),
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    published_at TEXT,
                    generated_at TEXT,
                    report_body BLOB,
                    report_digest TEXT
                );
                CREATE UNIQUE INDEX one_running_epoch ON epochs ((1)) WHERE status = 'running';
                CREATE UNIQUE INDEX one_finalized_source_epoch
                    ON epochs (source_epoch) WHERE status IN ('complete', 'published');

                CREATE TABLE challenges (
                    challenge_id TEXT PRIMARY KEY,
                    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
                    hotkey TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('issued', 'verified', 'failed', 'abandoned')),
                    work_units REAL NOT NULL DEFAULT 0 CHECK (work_units >= 0),
                    issued_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE epoch_attestations (
                    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
                    hotkey TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (verdict = 'VERIFIED'),
                    tee_type TEXT NOT NULL CHECK (tee_type = 'TDX'),
                    workload TEXT NOT NULL CHECK (workload = 'CPU'),
                    evidence_digest TEXT NOT NULL,
                    attested_at TEXT NOT NULL,
                    PRIMARY KEY (epoch_id, hotkey)
                );

                CREATE TABLE epoch_scores (
                    epoch_id INTEGER NOT NULL REFERENCES epochs(epoch_id),
                    hotkey TEXT NOT NULL,
                    work_units REAL NOT NULL CHECK (work_units >= 0),
                    score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
                    PRIMARY KEY (epoch_id, hotkey)
                );
                """
            )
            cx.execute(
                "INSERT INTO epochs (source_epoch, status, started_at, completed_at, "
                "generated_at, report_body, report_digest) VALUES "
                "(1, 'complete', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:01+00:00', "
                "'2020-01-01T00:00:00+00:00', ?, 'deadbeef')",
                (b'{"complete":true}',),
            )
            # Real child rows in all three tables that reference `epochs`, so
            # migration regression tests can assert they survive the rebuild
            # untouched (not just that the schema looks right).
            cx.execute(
                "INSERT INTO challenges "
                "(challenge_id, epoch_id, hotkey, status, work_units, issued_at, resolved_at) "
                "VALUES ('legacy-challenge', 1, 'hk', 'verified', 5, "
                "'2020-01-01T00:00:00+00:00', '2020-01-01T00:00:01+00:00')"
            )
            cx.execute(
                "INSERT INTO epoch_attestations "
                "(epoch_id, hotkey, verdict, tee_type, workload, evidence_digest, attested_at) "
                "VALUES (1, 'hk', 'VERIFIED', 'TDX', 'CPU', 'evidence-hk', "
                "'2020-01-01T00:00:00+00:00')"
            )
            cx.execute(
                "INSERT INTO epoch_scores (epoch_id, hotkey, work_units, score) VALUES (1, 'hk', 5, 1.0)"
            )
            cx.commit()
        finally:
            cx.close()

    def test_legacy_ledger_migrates_and_supports_abandon(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)

        ledger = Ledger(path)
        row = ledger.get_epoch(1)
        assert row["status"] == "complete"
        assert row["abandon_reason"] is None
        assert row["abandoned_at"] is None
        assert bytes(row["report_body"]) == b'{"complete":true}'

        # Existing invariants (one running epoch, source-epoch uniqueness) still hold.
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)

        ledger.abandon_completed_epoch(1, "legacy report too old for first ingest")
        migrated = ledger.get_epoch(1)
        assert migrated["status"] == "abandoned"
        assert migrated["abandon_reason"] == "legacy report too old for first ingest"
        assert ledger.begin_epoch(2)

    def test_migration_is_idempotent_across_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)
        Ledger(path).close()
        # A second open (already migrated) must not error or re-migrate.
        ledger = Ledger(path)
        assert ledger.get_epoch(1)["status"] == "complete"
        ledger.abandon_completed_epoch(1, "reason")
        assert ledger.get_epoch(1)["status"] == "abandoned"

    def test_refuses_to_open_with_leftover_pre_abandon_table(self, tmp_path: Path) -> None:
        """A stranded rename-aside table from an interrupted migration must be refused.

        This reproduces exactly what an old, non-atomic migration could leave
        behind if interrupted right after the rename: the rename-aside table
        holding all the real history, plus a brand new (empty-of-history)
        ``epochs`` table that already has the current schema. Without an
        explicit check, opening this file would treat migration as already
        done and silently proceed on the fresh, historyless table.
        """
        import sqlite3 as _sqlite3

        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)

        cx = _sqlite3.connect(str(path))
        try:
            cx.execute("DROP INDEX one_running_epoch")
            cx.execute("DROP INDEX one_finalized_source_epoch")
            cx.execute("ALTER TABLE epochs RENAME TO epochs_pre_abandon_migration")
            cx.execute(
                "CREATE TABLE epochs ("
                "epoch_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "source_epoch INTEGER NOT NULL, "
                "status TEXT NOT NULL CHECK ("
                "status IN ('running', 'aborted', 'complete', 'published', 'abandoned')"
                "), "
                "started_at TEXT NOT NULL, "
                "completed_at TEXT, "
                "published_at TEXT, "
                "generated_at TEXT, "
                "report_body BLOB, "
                "report_digest TEXT, "
                "abandoned_at TEXT, "
                "abandon_reason TEXT"
                ")"
            )
            cx.commit()
        finally:
            cx.close()

        with pytest.raises(LedgerError, match="leftover 'epochs_pre_abandon_migration'"):
            Ledger(path)

        # The refusal must not have mutated anything further: both tables
        # are exactly as this test left them for manual operator recovery.
        verify_cx = _sqlite3.connect(str(path))
        try:
            tables = {
                row[0]
                for row in verify_cx.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            assert "epochs_pre_abandon_migration" in tables
            assert "epochs" in tables
            stranded_row = verify_cx.execute(
                "SELECT report_digest FROM epochs_pre_abandon_migration WHERE epoch_id = 1"
            ).fetchone()
            assert stranded_row == ("deadbeef",)
        finally:
            verify_cx.close()

    def test_rolls_back_atomically_when_copy_step_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An error injected mid-rebuild must roll back the whole create+copy+drop+rename.

        Proves the fix for the original bug: because the rebuild runs inside
        one explicit transaction instead of `executescript` (which
        auto-commits), a failure partway through -- here, the row-copy INSERT
        into the throwaway temp table -- undoes the temp table creation
        together with anything after it. `epochs` is left exactly as it was,
        with no `epochs_migration_new_*` temp table stranded, and `PRAGMA
        foreign_keys` is restored even though migration failed.
        """
        import sqlite3 as _sqlite3

        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)

        class _InjectingConnection(_sqlite3.Connection):
            """Fails the migration's row-copy INSERT, simulating e.g. a full disk."""

            def execute(self, sql, *args, **kwargs):  # type: ignore[override]
                if isinstance(sql, str) and sql.startswith(
                    f"INSERT INTO {_EPOCHS_MIGRATION_TEMP_PREFIX}"
                ):
                    raise _sqlite3.OperationalError("injected copy failure")
                return super().execute(sql, *args, **kwargs)

        real_connect = _sqlite3.connect
        created_connections: list[_sqlite3.Connection] = []

        def connect_with_injection(*args, **kwargs):
            kwargs["factory"] = _InjectingConnection
            connection = real_connect(*args, **kwargs)
            created_connections.append(connection)
            return connection

        with monkeypatch.context() as patched:
            patched.setattr(_sqlite3, "connect", connect_with_injection)
            with pytest.raises(LedgerError, match="failed to migrate"):
                Ledger(path)

        assert len(created_connections) == 1
        failed_connection = created_connections[0]
        # PRAGMA foreign_keys is per-connection state, never persisted to disk,
        # so this is the only way to observe that the OFF/ON toggle around the
        # rebuild was restored correctly on the failure path.
        assert failed_connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        failed_connection.close()

        verify_cx = _sqlite3.connect(str(path))
        try:
            tables = {
                row[0]
                for row in verify_cx.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            assert not any(name.startswith(_EPOCHS_MIGRATION_TEMP_PREFIX) for name in tables)
            assert "epochs_pre_abandon_migration" not in tables
            assert "epochs" in tables
            columns = {row[1] for row in verify_cx.execute("PRAGMA table_info(epochs)")}
            assert "abandon_reason" not in columns
            row = verify_cx.execute(
                "SELECT source_epoch, status, report_digest FROM epochs WHERE epoch_id = 1"
            ).fetchone()
            assert row == (1, "complete", "deadbeef")
            # The child rows that predate the failed migration attempt must
            # be untouched: rollback undid the parent-table rebuild, and it
            # never touched child tables at all.
            challenge_row = verify_cx.execute(
                "SELECT epoch_id, status FROM challenges WHERE challenge_id = 'legacy-challenge'"
            ).fetchone()
            assert challenge_row == (1, "verified")
            fk_violations = verify_cx.execute("PRAGMA foreign_key_check").fetchall()
            assert fk_violations == []
        finally:
            verify_cx.close()

        # A later, uninterrupted open still migrates cleanly.
        ledger = Ledger(path)
        assert ledger.get_epoch(1)["abandon_reason"] is None

    def test_refuses_to_open_with_leftover_new_temp_migration_table(self, tmp_path: Path) -> None:
        """A stranded temp table from an interrupted *new-style* rebuild is refused.

        Mirrors `test_refuses_to_open_with_leftover_pre_abandon_table` but for
        the current rebuild strategy: if the process died between creating
        the `epochs_migration_new_*` temp table and dropping it (e.g. right
        after the rename, before `DROP TABLE` of the old temp name would ever
        run -- here simulated by leaving the temp table around directly),
        the leftover must be surfaced rather than silently ignored on reopen.
        """
        import sqlite3 as _sqlite3

        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)

        leftover_name = f"{_EPOCHS_MIGRATION_TEMP_PREFIX}deadbeefcafef00d"
        cx = _sqlite3.connect(str(path))
        try:
            cx.execute(f"CREATE TABLE {leftover_name} (epoch_id INTEGER PRIMARY KEY)")
            cx.commit()
        finally:
            cx.close()

        with pytest.raises(LedgerError, match=f"leftover {leftover_name!r}"):
            Ledger(path)

        # The refusal must not have mutated anything: the original `epochs`
        # table and the stray temp table are both exactly as left here.
        verify_cx = _sqlite3.connect(str(path))
        try:
            tables = {
                row[0]
                for row in verify_cx.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            assert leftover_name in tables
            assert "epochs" in tables
            columns = {row[1] for row in verify_cx.execute("PRAGMA table_info(epochs)")}
            assert "abandon_reason" not in columns
        finally:
            verify_cx.close()

    def test_migration_preserves_child_rows_and_never_leaves_dangling_references(
        self, tmp_path: Path
    ) -> None:
        """End-to-end regression test for the rename-based-FK-rewrite bug.

        Builds a legacy ledger with real rows in all three child tables
        (`challenges`, `epoch_attestations`, `epoch_scores`), migrates it, and
        asserts: `PRAGMA foreign_key_check` is clean, no child table's stored
        schema mentions any `epochs_migration_new_*` temp name (the exact
        defect that made `no such table: main.epochs_pre_abandon_migration`
        possible under the old rename-the-real-table approach), the
        pre-migration child rows are still there and still valid, and both
        new epochs and new child rows referencing them can be created after
        migration.
        """
        import sqlite3 as _sqlite3

        path = tmp_path / "legacy.sqlite3"
        self._create_legacy_schema(path)

        ledger = Ledger(path)

        raw = _sqlite3.connect(str(path))
        try:
            assert raw.execute("PRAGMA foreign_key_check").fetchall() == []

            child_sql = {
                row[0]: row[1]
                for row in raw.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
                    "AND name IN ('challenges', 'epoch_attestations', 'epoch_scores')"
                )
            }
            assert set(child_sql) == {"challenges", "epoch_attestations", "epoch_scores"}
            for table_name, sql in child_sql.items():
                assert "epochs(" in sql or "epochs (" in sql, table_name
                assert _EPOCHS_MIGRATION_TEMP_PREFIX not in sql, table_name
                assert "epochs_pre_abandon_migration" not in sql, table_name

            # No table anywhere -- parent or child -- mentions a temp name.
            all_sql = [
                row[0]
                for row in raw.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND sql IS NOT NULL"
                )
            ]
            assert not any(_EPOCHS_MIGRATION_TEMP_PREFIX in sql for sql in all_sql)

            # Pre-migration child rows for epoch 1 survived the rebuild.
            assert raw.execute(
                "SELECT epoch_id, hotkey, status FROM challenges WHERE challenge_id = 'legacy-challenge'"
            ).fetchone() == (1, "hk", "verified")
            assert raw.execute(
                "SELECT epoch_id, hotkey, evidence_digest, policy_mode FROM epoch_attestations "
                "WHERE epoch_id = 1 AND hotkey = 'hk'"
            ).fetchone() == (1, "hk", "evidence-hk", "compatibility")
            assert raw.execute(
                "SELECT epoch_id, hotkey, score FROM epoch_scores WHERE epoch_id = 1 AND hotkey = 'hk'"
            ).fetchone() == (1, "hk", 1.0)
        finally:
            raw.close()

        # New activity against the migrated schema works end to end: new
        # epoch, new challenge/attestation/score rows referencing it, and the
        # old epoch's data is unaffected.
        ledger.abandon_completed_epoch(1, "legacy report too old for first ingest")
        new_epoch_id = ledger.begin_epoch(2)
        ledger.issue_challenge("new-challenge", "hk2", new_epoch_id)
        ledger.resolve_challenge("new-challenge", "verified", 10, validator_derived=True)
        attest(ledger, new_epoch_id, "hk2")
        scores = ledger.complete_epoch(new_epoch_id, {"hk2"})
        assert scores == {"hk2": 1.0}
        assert ledger.get_epoch(1)["status"] == "abandoned"

        raw = _sqlite3.connect(str(path))
        try:
            assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
            assert raw.execute(
                "SELECT epoch_id, hotkey, status FROM challenges WHERE challenge_id = 'legacy-challenge'"
            ).fetchone() == (1, "hk", "verified")
            assert raw.execute(
                "SELECT epoch_id, hotkey, status FROM challenges WHERE challenge_id = 'new-challenge'"
            ).fetchone() == (new_epoch_id, "hk2", "verified")
        finally:
            raw.close()
        ledger.close()


class FakeHeaders(dict):
    pass


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class FakeResponse:
    def __init__(
        self,
        chunks: list[bytes | BaseException],
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.chunks = chunks
        self.status = status
        self.headers = FakeHeaders(headers or {})
        self.fp = type("FP", (), {})()
        self.fp.raw = type("Raw", (), {"_sock": FakeSocket()})()

    def getcode(self) -> int:
        return self.status

    def read(self, _: int) -> bytes:
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        pass


def make_poster(**kwargs) -> Poster:
    return Poster(
        "https://publisher.example/v1/external-scores/violet",
        "bearer-token",
        "hmac-secret",
        **kwargs,
    )


class TestPoster:
    def test_requires_https_and_fixed_public_route(self) -> None:
        with pytest.raises(PosterError, match="HTTPS"):
            Poster(
                "http://publisher.example/v1/external-scores/violet",
                "token",
                "secret",
            )
        Poster(
            "http://localhost/v1/external-scores/violet",
            "token",
            "secret",
            allow_http_for_tests=True,
        )
        with pytest.raises(PosterError, match="endpoint path"):
            Poster("https://publisher.example/other", "token", "secret")

    @pytest.mark.parametrize("secret", ["", b""])
    def test_requires_nonempty_hmac_secret(self, secret: str | bytes) -> None:
        with pytest.raises(PosterError, match="HMAC secret must be a nonempty"):
            Poster(
                "https://publisher.example/v1/external-scores/violet",
                "token",
                secret,
            )

    def test_posts_exact_body_with_required_headers_and_signature(self) -> None:
        poster = make_poster()
        body = b'{"complete":true,"epoch":1}'
        response = FakeResponse([b'{"status":"accepted"}', b""])
        captured = {}

        def open_request(request, *, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return response

        poster._opener.open = open_request
        assert poster.post(body) == {"status": "accepted"}
        request = captured["request"]
        assert request.data is body
        assert request.get_method() == "POST"
        assert request.get_header("Authorization") == "Bearer bearer-token"
        assert request.get_header("Content-type") == "application/json"
        expected = hmac.new(b"hmac-secret", body, hashlib.sha256).hexdigest()
        assert request.get_header("X-cathedral-external-signature") == expected
        assert captured["timeout"] == poster.connect_timeout
        assert response.fp.raw._sock.timeouts

    def test_retry_posts_same_bytes_without_mutation(self) -> None:
        poster = make_poster()
        body = b'{"scores":[{"miner_hotkey":"hk","score":1.0}]}'
        seen: list[bytes] = []

        def open_request(request, *, timeout):
            seen.append(request.data)
            return FakeResponse([b'{"status":"accepted"}', b""])

        poster._opener.open = open_request
        poster.post(body)
        poster.post(body)
        assert seen == [body, body]

    def test_redirect_is_refused(self) -> None:
        poster = make_poster()

        def redirect(*args, **kwargs):
            raise urllib.error.HTTPError(
                poster.endpoint, 302, "Found", {"Location": "https://evil.example"}, None
            )

        poster._opener.open = redirect
        with pytest.raises(PosterError, match="redirect refused"):
            poster.post(b"{}")

    def test_connect_and_read_timeout_fail_closed(self) -> None:
        poster = make_poster(connect_timeout=1, read_timeout=2, total_timeout=3)
        poster._opener.open = lambda *args, **kwargs: (_ for _ in ()).throw(
            urllib.error.URLError(socket.timeout("connect timed out"))
        )
        with pytest.raises(PosterError, match="timed out"):
            poster.post(b"{}")

        poster._opener.open = lambda *args, **kwargs: FakeResponse(
            [socket.timeout("read timed out")]
        )
        with pytest.raises(PosterError, match="timed out"):
            poster.post(b"{}")

    def test_total_deadline_is_enforced(self) -> None:
        poster = make_poster(total_timeout=1)
        response = FakeResponse([b"{}", b""])
        poster._opener.open = lambda *args, **kwargs: response
        with patch("cathedral.poster.time.monotonic", side_effect=[10.0, 10.1, 11.1]):
            with pytest.raises(PosterError, match="total request deadline"):
                poster.post(b"{}")

    def test_bounded_response_and_json_object_required(self) -> None:
        poster = make_poster(response_cap_bytes=4)
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"12345"])
        with pytest.raises(PosterError, match="exceeds configured cap"):
            poster.post(b"{}")

        poster = make_poster()
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"[]", b""])
        with pytest.raises(PosterError, match="JSON must be an object"):
            poster.post(b"{}")

    @pytest.mark.parametrize(
        "body",
        [b"{}", b'{"status":"rejected"}', b'{"status":true}'],
    )
    def test_requires_accepted_acknowledgement(self, body: bytes) -> None:
        poster = make_poster()
        poster._opener.open = lambda *args, **kwargs: FakeResponse([body, b""])
        with pytest.raises(PosterError, match="acknowledgement status"):
            poster.post(b"{}")

    def test_non_2xx_is_rejected(self) -> None:
        poster = make_poster()
        poster._opener.open = lambda *args, **kwargs: FakeResponse(
            [b'{"status":"accepted"}'], status=299
        )
        assert poster.post(b"{}") == {"status": "accepted"}
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"{}"], status=300)
        with pytest.raises(PosterError, match="unexpected HTTP status 300"):
            poster.post(b"{}")

    def test_only_bytes_are_accepted(self) -> None:
        poster = make_poster()
        with pytest.raises(PosterError, match="exact persisted bytes"):
            poster.post({"scores": []})  # type: ignore[arg-type]


def test_ledger_report_is_posted_byte_for_byte_and_then_marked() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    verified_work(ledger, epoch_id, "challenge", "hk", 1)
    attest(ledger, epoch_id, "hk")
    ledger.complete_epoch(epoch_id, {"hk"})
    body = ledger.report_bytes(epoch_id)

    poster = make_poster()
    seen: list[bytes] = []

    def open_request(request, *, timeout):
        seen.append(request.data)
        return FakeResponse([b'{"status":"accepted"}', b""])

    poster._opener.open = open_request
    assert ledger.post_and_mark_published(epoch_id, poster) == {"status": "accepted"}
    assert seen == [body]
    assert ledger.get_epoch(epoch_id)["status"] == "published"


def test_post_and_mark_leaves_epoch_complete_without_accepted_ack() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    ledger.complete_epoch(epoch_id, set())

    class RejectingPoster:
        def post(self, report_body: bytes) -> dict:
            return {"status": "rejected"}

    with pytest.raises(LedgerError, match="acknowledgement status"):
        ledger.post_and_mark_published(epoch_id, RejectingPoster())
    assert ledger.get_epoch(epoch_id)["status"] == "complete"


def test_post_and_mark_does_not_hold_database_lock_during_network_call() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    ledger.complete_epoch(epoch_id, set())

    class InspectingPoster:
        def post(self, report_body: bytes) -> dict:
            finished = threading.Event()

            def inspect() -> None:
                assert ledger.blocking_epoch()["epoch_id"] == epoch_id
                finished.set()

            thread = threading.Thread(target=inspect)
            thread.start()
            thread.join(timeout=1)
            assert finished.is_set(), "ledger lock was held during network I/O"
            return {"status": "accepted"}

    ledger.post_and_mark_published(epoch_id, InspectingPoster())
    assert ledger.get_epoch(epoch_id)["status"] == "published"
