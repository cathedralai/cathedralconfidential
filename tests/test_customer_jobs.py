"""Durable customer-job queue state-machine tests."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cathedral.lanes.sat import CUSTOMER_SAT_WORK_UNITS, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import CustomerJobLease, Ledger, LedgerError


def _item(*, seed: int = 7, clauses: list[list[int]] | None = None) -> SatWorkItem:
    instance = SatInstance(n_vars=3, clauses=clauses or [[1, -2, 3], [-1, 2]])
    return SatWorkItem(instance, seed, _compute_challenge_id(instance, seed))


def _claim(ledger: Ledger, epoch_id: int, owner: str = "worker") -> CustomerJobLease:
    lease = ledger.claim_customer_job(
        owner,
        epoch_id,
        lease_seconds=60,
        max_attempts=3,
    )
    assert lease is not None
    return lease


def test_enqueue_is_idempotent_only_for_identical_payload(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        first = ledger.enqueue_customer_job(
            _item(), customer_id="customer-a", idempotency_key="request-1"
        )
        replay = ledger.enqueue_customer_job(
            _item(), customer_id="customer-a", idempotency_key="request-1"
        )
        assert replay.job_id == first.job_id
        assert ledger.customer_job_counts()["queued"] == 1

        with pytest.raises(LedgerError, match="different work"):
            ledger.enqueue_customer_job(
                _item(seed=8), customer_id="customer-a", idempotency_key="request-1"
            )
        other = ledger.enqueue_customer_job(
            _item(seed=8), customer_id="customer-b", idempotency_key="request-1"
        )
        assert other.customer_id == "customer-b"


def test_oversized_customer_payload_is_rejected_before_persistence(tmp_path: Path) -> None:
    clauses = [[1] * 8 for _ in range(8192)]
    item = _item(clauses=clauses)
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        with pytest.raises(LedgerError, match="request size"):
            ledger.enqueue_customer_job(item)
        assert ledger.customer_job_counts()["queued"] == 0


def test_two_ledger_connections_cannot_double_claim(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    first = Ledger(path)
    second = Ledger(path)
    try:
        first.enqueue_customer_job(_item())
        epoch_id = first.begin_epoch(1)
        barrier = threading.Barrier(2)
        claims: list[CustomerJobLease | None] = []

        def claim(ledger: Ledger, owner: str) -> None:
            barrier.wait()
            claims.append(
                ledger.claim_customer_job(
                    owner,
                    epoch_id,
                    lease_seconds=60,
                    max_attempts=3,
                )
            )

        threads = [
            threading.Thread(target=claim, args=(first, "worker-a")),
            threading.Thread(target=claim, args=(second, "worker-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(lease is not None for lease in claims) == 1
        assert first.customer_job_counts()["leased"] == 1
    finally:
        first.close()
        second.close()


def test_concurrent_submission_respects_global_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cathedral.ledger.MAX_ACTIVE_CUSTOMER_JOBS", 1)
    path = tmp_path / "ledger.sqlite"
    first = Ledger(path)
    second = Ledger(path)
    barrier = threading.Barrier(2)
    submitted: list[str] = []
    errors: list[str] = []

    def enqueue(ledger: Ledger, customer_id: str, seed: int) -> None:
        barrier.wait()
        try:
            submitted.append(
                ledger.enqueue_customer_job(
                    _item(seed=seed),
                    customer_id=customer_id,
                ).job_id
            )
        except LedgerError as exc:
            errors.append(str(exc))

    threads = [
        threading.Thread(target=enqueue, args=(first, "customer-a", 1)),
        threading.Thread(target=enqueue, args=(second, "customer-b", 2)),
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(submitted) == 1
        assert errors == ["customer job queue capacity reached"]
        assert first.customer_job_counts()["queued"] == 1
    finally:
        first.close()
        second.close()


def test_per_customer_active_quota_is_independent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("cathedral.ledger.MAX_ACTIVE_CUSTOMER_JOBS_PER_CUSTOMER", 1)
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        ledger.enqueue_customer_job(_item(seed=1), customer_id="customer-a")
        with pytest.raises(LedgerError, match="active-job quota"):
            ledger.enqueue_customer_job(_item(seed=2), customer_id="customer-a")
        ledger.enqueue_customer_job(_item(seed=2), customer_id="customer-b")
        assert ledger.customer_job_counts()["queued"] == 2


def test_total_ledger_storage_budget_rejects_before_insert(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("cathedral.ledger.MAX_CUSTOMER_JOB_STORAGE_BYTES", 1)
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        with pytest.raises(LedgerError, match="storage capacity"):
            ledger.enqueue_customer_job(_item(), customer_id="customer-a")
        assert ledger.customer_job_counts()["queued"] == 0


def test_success_atomically_persists_validator_normalized_result(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        lease = _claim(ledger, ledger.begin_epoch(1))
        result = {
            "satisfiable": True,
            "assignment": [-1, -2, 3],
            "work_units": CUSTOMER_SAT_WORK_UNITS,
            "challenge_id": lease.challenge_id,
            "assigned_hotkey": lease.owner_hotkey,
        }
        ledger.resolve_challenge(
            lease.challenge_id,
            "verified",
            CUSTOMER_SAT_WORK_UNITS,
            validator_derived=True,
            customer_lease=lease,
            customer_disposition="succeeded",
            customer_result=result,
        )

        snapshot = ledger.customer_job(submitted.job_id)
        assert snapshot.status == "succeeded"
        assert snapshot.attempt_count == 1
        assert dict(snapshot.result or {}) == result
        assert snapshot.lease_owner is None


def test_transport_retry_is_bounded_and_uses_fresh_challenge(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        epoch_id = ledger.begin_epoch(1)
        first = _claim(ledger, epoch_id)
        ledger.resolve_challenge(
            first.challenge_id,
            "failed",
            customer_lease=first,
            customer_disposition="retry",
            customer_error="worker transport failed",
            customer_max_attempts=2,
        )
        assert ledger.customer_job(submitted.job_id).status == "queued"

        second = _claim(ledger, epoch_id)
        assert second.attempt == 2
        assert second.challenge_id != first.challenge_id
        ledger.resolve_challenge(
            second.challenge_id,
            "failed",
            customer_lease=second,
            customer_disposition="retry",
            customer_error="worker transport failed again",
            customer_max_attempts=2,
        )
        snapshot = ledger.customer_job(submitted.job_id)
        assert snapshot.status == "failed"
        assert snapshot.attempt_count == 2


def test_stale_or_wrong_lease_cannot_complete_job(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        lease = _claim(ledger, ledger.begin_epoch(1))
        forged = replace(lease, lease_token="0" * 32)

        with pytest.raises(LedgerError, match="stale"):
            ledger.resolve_challenge(
                lease.challenge_id,
                "failed",
                customer_lease=forged,
                customer_disposition="failed",
                customer_error="invalid certificate",
            )
        assert ledger.customer_job(submitted.job_id).status == "leased"

        ledger.resolve_challenge(
            lease.challenge_id,
            "failed",
            customer_lease=lease,
            customer_disposition="failed",
            customer_error="invalid certificate",
        )
        assert ledger.customer_job(submitted.job_id).status == "failed"


def test_invalid_result_cannot_half_resolve_challenge_or_job(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        lease = _claim(ledger, ledger.begin_epoch(1))
        with pytest.raises(LedgerError, match="result schema"):
            ledger.resolve_challenge(
                lease.challenge_id,
                "verified",
                CUSTOMER_SAT_WORK_UNITS,
                validator_derived=True,
                customer_lease=lease,
                customer_disposition="succeeded",
                customer_result={"oversized": "x" * (64 * 1024)},
            )
        assert ledger.customer_job(submitted.job_id).status == "leased"
        challenge = ledger._connection.execute(  # noqa: SLF001
            "SELECT status FROM challenges WHERE challenge_id = ?", (lease.challenge_id,)
        ).fetchone()
        assert challenge["status"] == "issued"


def test_unsat_result_cannot_be_persisted_as_customer_success(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item(clauses=[[1], [-1]]))
        lease = _claim(ledger, ledger.begin_epoch(1))
        with pytest.raises(LedgerError, match="satisfiable assignment witness"):
            ledger.resolve_challenge(
                lease.challenge_id,
                "verified",
                CUSTOMER_SAT_WORK_UNITS,
                validator_derived=True,
                customer_lease=lease,
                customer_disposition="succeeded",
                customer_result={
                    "satisfiable": False,
                    "assignment": None,
                    "work_units": CUSTOMER_SAT_WORK_UNITS,
                    "challenge_id": lease.challenge_id,
                    "assigned_hotkey": lease.owner_hotkey,
                },
            )
        assert ledger.customer_job(submitted.job_id).status == "leased"
        challenge = ledger._connection.execute(  # noqa: SLF001
            "SELECT status FROM challenges WHERE challenge_id = ?", (lease.challenge_id,)
        ).fetchone()
        assert challenge["status"] == "issued"


def test_terminal_history_can_be_pruned_for_storage_reuse(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item(), customer_id="customer-a")
        lease = _claim(ledger, ledger.begin_epoch(1))
        ledger.resolve_challenge(
            lease.challenge_id,
            "failed",
            customer_lease=lease,
            customer_disposition="failed",
            customer_error="terminal test failure",
        )
        removed = ledger.prune_customer_jobs(
            datetime.now(timezone.utc) + timedelta(seconds=1),
            customer_id="customer-a",
        )
        assert removed == 1
        assert ledger.customer_job_counts()["failed"] == 0
        with pytest.raises(LedgerError, match="not found"):
            ledger.customer_job(submitted.job_id)


def test_expired_lease_is_abandoned_and_reclaimed(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        epoch_id = ledger.begin_epoch(1)
        first = _claim(ledger, epoch_id, "worker-a")
        ledger._connection.execute(  # noqa: SLF001 - controlled corruption clock fixture
            "UPDATE customer_jobs SET lease_expires_at = ? WHERE job_id = ?",
            ("2000-01-01T00:00:00+00:00", submitted.job_id),
        )

        second = _claim(ledger, epoch_id, "worker-b")
        assert second.attempt == 2
        assert second.challenge_id != first.challenge_id
        old = ledger._connection.execute(  # noqa: SLF001
            "SELECT status FROM challenges WHERE challenge_id = ?", (first.challenge_id,)
        ).fetchone()
        assert old["status"] == "abandoned"

        with pytest.raises(LedgerError, match="already abandoned|stale"):
            ledger.resolve_challenge(
                first.challenge_id,
                "failed",
                customer_lease=first,
                customer_disposition="failed",
                customer_error="late result",
            )


def test_aborting_epoch_requeues_customer_job_and_abandons_challenge(tmp_path: Path) -> None:
    with Ledger(tmp_path / "ledger.sqlite") as ledger:
        submitted = ledger.enqueue_customer_job(_item())
        epoch_id = ledger.begin_epoch(1)
        lease = _claim(ledger, epoch_id)
        ledger.abort_epoch(epoch_id)

        snapshot = ledger.customer_job(submitted.job_id)
        assert snapshot.status == "queued"
        assert snapshot.lease_owner is None
        challenge = ledger._connection.execute(  # noqa: SLF001
            "SELECT status FROM challenges WHERE challenge_id = ?", (lease.challenge_id,)
        ).fetchone()
        assert challenge["status"] == "abandoned"
