"""Worker lifecycle, retry, persistence, and concurrency boundaries."""

from __future__ import annotations

import sqlite3
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cathedral.assurance import attestation_claims
from cathedral.common import Attested, Policy, Tier
from cathedral.cli import build_parser
from cathedral.enroll import RegistryStore
from cathedral.ledger import Ledger
from cathedral.lifecycle import (
    ALLOWED_TRANSITIONS,
    LifecycleError,
    LifecycleReason,
    SingleFlightReattestor,
    WorkerLifecycleState,
    canonical_utc,
    require_transition,
    retry_delay_seconds,
)
from cathedral.runtime import ConfidentialRuntime, RuntimeConfig


START = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
REGISTRY_DIGEST = "sha256:" + "a" * 64


@dataclass
class MutableClock:
    now: datetime = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def _policy(measurement: str = "measurement") -> Policy:
    return Policy(
        allowed_measurements={measurement},
        registry_release=1,
        registry_digest=REGISTRY_DIGEST,
    )


def _attested(at: datetime = START, measurement: str = "measurement") -> Attested:
    policy = _policy(measurement)
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id="chip-1",
        measurement=measurement,
        tcb=1,
        assurance=attestation_claims(
            b"quote",
            policy,
            verified_at=canonical_utc(at),
        ),
    )


def _store(tmp_path: Path, clock: MutableClock, *, ttl: int = 60) -> RegistryStore:
    store = RegistryStore(
        str(tmp_path / "registry.sqlite"),
        verification_ttl_seconds=ttl,
        clock=clock,
    )
    store.enroll("worker", "https://worker.example")
    return store


def _record_attested(store: RegistryStore, at: datetime = START) -> None:
    store.record_verdict(
        "worker",
        _attested(at),
        policy_registry_release=1,
        policy_registry_digest=REGISTRY_DIGEST,
    )


def test_closed_transition_table_accepts_every_declared_edge_and_rejects_all_others():
    states = tuple(WorkerLifecycleState)
    for current in states:
        for target in states:
            if target in ALLOWED_TRANSITIONS[current]:
                require_transition(current, target)
            else:
                with pytest.raises(LifecycleError, match="illegal"):
                    require_transition(current, target)


def test_freshness_boundary_and_clock_rollback_fail_closed(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    _record_attested(store)

    clock.advance(59)
    assert store.lifecycle_snapshot("worker").state is WorkerLifecycleState.ATTESTED

    clock.advance(1)
    stale = store.lifecycle_snapshot("worker")
    assert stale.state is WorkerLifecycleState.STALE
    assert stale.reason is LifecycleReason.EVIDENCE_EXPIRED

    clock.now -= timedelta(microseconds=1)
    with pytest.raises(LifecycleError, match="clock moved backwards"):
        store.lifecycle_snapshot("worker")


def test_legacy_board_status_uses_the_same_exact_expiry_boundary(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    verified_at = canonical_utc(START)
    assert store._effective_status("VERIFIED", verified_at, START + timedelta(seconds=59)) == (
        "VERIFIED"
    )
    assert store._effective_status("VERIFIED", verified_at, START + timedelta(seconds=60)) == (
        "STALE"
    )


def test_bounded_retry_schedule_survives_restart_and_exhausts_to_failed(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    _record_attested(store)
    initial = store.lifecycle_snapshot("worker", materialize_freshness=False)

    clock.advance(10)
    retry = store.record_refresh_failure(
        "worker",
        attempt=1,
        maximum_attempts=3,
        retry_base_seconds=5,
        retry_maximum_seconds=20,
        retry_jitter_seconds=0,
        expected_generation=initial.generation,
        expected_revision=initial.revision,
        operator_detail="temporary timeout",
    )
    assert retry.state is WorkerLifecycleState.ATTESTED
    assert retry.next_retry_at == clock.now + timedelta(seconds=5)
    assert store.due_refreshes(refresh_ahead_seconds=60) == ()

    reopened = RegistryStore(
        str(tmp_path / "registry.sqlite"),
        verification_ttl_seconds=60,
        clock=clock,
    )
    clock.advance(5)
    assert [item.hotkey for item in reopened.due_refreshes(refresh_ahead_seconds=60)] == [
        "worker"
    ]

    clock.advance(45)
    stale = reopened.lifecycle_snapshot("worker")
    assert stale.state is WorkerLifecycleState.STALE
    retry = reopened.record_refresh_failure(
        "worker",
        attempt=2,
        maximum_attempts=3,
        retry_base_seconds=5,
        retry_maximum_seconds=20,
        retry_jitter_seconds=0,
        expected_generation=stale.generation,
        expected_revision=stale.revision,
    )
    assert retry.state is WorkerLifecycleState.STALE

    clock.advance(10)
    failed = reopened.record_refresh_failure(
        "worker",
        attempt=3,
        maximum_attempts=3,
        retry_base_seconds=5,
        retry_maximum_seconds=20,
        retry_jitter_seconds=0,
        expected_generation=retry.generation,
        expected_revision=retry.revision,
    )
    assert failed.state is WorkerLifecycleState.FAILED
    assert failed.reason is LifecycleReason.RETRY_EXHAUSTED
    assert reopened.due_refreshes(refresh_ahead_seconds=60) == ()


def test_first_attestation_failure_remains_pending_with_a_bounded_retry(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    initial = store.lifecycle_snapshot("worker")
    clock.advance(1)
    retry = store.record_refresh_failure(
        "worker",
        attempt=1,
        maximum_attempts=3,
        retry_base_seconds=5,
        retry_maximum_seconds=20,
        retry_jitter_seconds=0,
        expected_generation=initial.generation,
        expected_revision=initial.revision,
    )
    assert retry.state is WorkerLifecycleState.PENDING
    assert retry.retry_count == 1
    assert retry.next_retry_at == clock.now + timedelta(seconds=5)


def test_retry_delay_is_deterministic_bounded_and_rejects_boolean_inputs():
    first = retry_delay_seconds(
        "worker",
        1,
        4,
        base_seconds=5,
        maximum_seconds=30,
        jitter_seconds=7,
    )
    assert first == retry_delay_seconds(
        "worker",
        1,
        4,
        base_seconds=5,
        maximum_seconds=30,
        jitter_seconds=7,
    )
    assert 5 <= first <= 30
    with pytest.raises(LifecycleError, match="retry policy"):
        retry_delay_seconds(
            "worker",
            True,
            1,
            base_seconds=5,
            maximum_seconds=30,
            jitter_seconds=0,
        )
    with pytest.raises(LifecycleError, match="retry policy"):
        retry_delay_seconds(
            "worker",
            1,
            1,
            base_seconds=True,
            maximum_seconds=30,
            jitter_seconds=0,
        )


def test_policy_revocation_is_offline_terminal_until_explicit_reenrollment(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    _record_attested(store)

    clock.advance(1)
    revoked = store.apply_lifecycle_policy(
        frozenset({"replacement-measurement"}),
        policy_registry_release=2,
        policy_registry_digest="sha256:" + "b" * 64,
    )
    assert len(revoked) == 1
    assert revoked[0].state is WorkerLifecycleState.REVOKED
    assert revoked[0].reason is LifecycleReason.POLICY_REVOKED
    assert store.due_refreshes(refresh_ahead_seconds=60) == ()
    with pytest.raises(LifecycleError, match="illegal"):
        store.transition_lifecycle(
            "worker",
            WorkerLifecycleState.ATTESTED,
            LifecycleReason.ATTESTATION_VERIFIED,
        )

    clock.advance(1)
    pending = store.reenroll_lifecycle("worker")
    assert pending.state is WorkerLifecycleState.PENDING
    assert pending.generation == revoked[0].generation + 1


def test_legacy_verified_rows_backfill_stale_without_exact_measurement(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    _record_attested(store)
    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TABLE worker_lifecycle_current")
        conn.execute("DROP TABLE worker_lifecycle_events")
        conn.execute("DROP TABLE worker_lifecycle_clock")

    reopened = RegistryStore(
        store.path,
        verification_ttl_seconds=60,
        clock=clock,
    )
    snapshot = reopened.lifecycle_snapshot("worker")
    assert snapshot.state is WorkerLifecycleState.STALE
    assert snapshot.reason is LifecycleReason.BACKFILL_STALE
    assert snapshot.measurement is None


def test_public_status_and_history_omit_operator_evidence(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    _record_attested(store)
    snapshot = store.lifecycle_snapshot("worker")

    public = snapshot.public_dict()
    operator = snapshot.operator_dict()
    public_history = store.lifecycle_history("worker")
    operator_history = store.lifecycle_history("worker", operator=True)

    assert "evidence_digest" not in public
    assert "measurement" not in public
    assert "operator_detail" not in public_history[-1]
    assert "event_id" not in public_history[-1]
    assert "revision" not in public_history[-1]
    assert operator["evidence_digest"] == snapshot.evidence_digest
    assert "event_id" in operator_history[-1]
    assert "revision" in operator_history[-1]
    assert operator_history[-1]["measurement"] == "measurement"


def test_lifecycle_cli_defaults_to_customer_safe_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "cli-registry.sqlite"
    store = RegistryStore(str(path))
    store.enroll("worker", "https://private-worker.example")
    parser = build_parser()

    args = parser.parse_args(
        [
            "lifecycle",
            "status",
            "--registry-db",
            str(path),
            "--hotkey",
            "worker",
        ]
    )
    assert args.func(args) == 0
    public = json.loads(capsys.readouterr().out)
    assert public["state"] == "pending"
    assert "measurement" not in public
    assert "evidence_digest" not in public
    assert "private-worker" not in json.dumps(public)

    args = parser.parse_args(
        [
            "lifecycle",
            "status",
            "--registry-db",
            str(path),
            "--hotkey",
            "worker",
            "--operator",
        ]
    )
    assert args.func(args) == 0
    operator = json.loads(capsys.readouterr().out)
    assert "measurement" in operator
    assert "evidence_digest" in operator


def test_lifecycle_cli_wires_reenrollment_and_retirement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "cli-operations.sqlite"
    store = RegistryStore(str(path))
    store.enroll("worker", "https://worker.example")
    store.transition_lifecycle(
        "worker",
        WorkerLifecycleState.FAILED,
        LifecycleReason.VERIFICATION_FAILED,
    )
    parser = build_parser()

    reenroll = parser.parse_args(
        [
            "lifecycle",
            "reenroll",
            "--registry-db",
            str(path),
            "--hotkey",
            "worker",
        ]
    )
    assert reenroll.func(reenroll) == 0
    reenrolled = json.loads(capsys.readouterr().out)
    assert reenrolled["state"] == "pending"
    assert reenrolled["generation"] == 2

    retire = parser.parse_args(
        [
            "lifecycle",
            "retire",
            "--registry-db",
            str(path),
            "--hotkey",
            "worker",
            "--removed",
        ]
    )
    assert retire.func(retire) == 0
    retired = json.loads(capsys.readouterr().out)
    assert retired["state"] == "retired"
    assert [event["to_state"] for event in store.lifecycle_history("worker")][-3:] == [
        "pending",
        "retiring",
        "retired",
    ]


def test_board_resamples_lifecycle_time_after_concurrent_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    store = _store(tmp_path, clock)
    writer = RegistryStore(store.path, clock=clock)
    original_effective_status = store._effective_status
    wrote = False

    def write_between_board_reads(status: str, verified_at: str | None, now: datetime) -> str:
        nonlocal wrote
        if not wrote:
            wrote = True
            clock.advance(1)
            writer.reenroll_lifecycle("worker")
        return original_effective_status(status, verified_at, now)

    monkeypatch.setattr(store, "_effective_status", write_between_board_reads)

    board = store.board()

    assert board["miners"][0]["lifecycle"]["generation"] == 2
    assert board["miners"][0]["lifecycle"]["state"] == "pending"


def test_probe_failure_rejects_invalid_retry_policy_without_writing(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    store = _store(tmp_path, clock)
    before = store.lifecycle_history("worker", operator=True)

    with pytest.raises(LifecycleError, match="retry policy"):
        store.record_probe_failure("worker", maximum_attempts="3")  # type: ignore[arg-type]

    assert store.lifecycle_history("worker", operator=True) == before
    assert store.lifecycle_snapshot("worker").retry_count == 0


def test_transition_event_and_current_projection_are_atomic(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    before = store.lifecycle_history("worker")
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "CREATE TRIGGER reject_lifecycle_projection BEFORE UPDATE "
            "ON worker_lifecycle_current BEGIN SELECT RAISE(ABORT, 'boom'); END"
        )
    clock.advance(1)
    with pytest.raises(sqlite3.DatabaseError, match="boom"):
        store.transition_lifecycle(
            "worker",
            WorkerLifecycleState.FAILED,
            LifecycleReason.VERIFICATION_FAILED,
        )
    assert store.lifecycle_history("worker") == before


def test_lifecycle_history_table_rejects_update_and_delete(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    before = store.lifecycle_history("worker", operator=True)
    with sqlite3.connect(store.path) as conn:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(
                "UPDATE worker_lifecycle_events SET reason = 'reenrolled'"
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM worker_lifecycle_events")
    assert store.lifecycle_history("worker", operator=True) == before


def test_stale_completion_cannot_overwrite_new_generation(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    old = store.lifecycle_snapshot("worker")
    clock.advance(1)
    current = store.reenroll_lifecycle("worker")
    with pytest.raises(LifecycleError, match="generation changed"):
        store.record_refresh_failure(
            "worker",
            attempt=1,
            maximum_attempts=3,
            expected_generation=old.generation,
            expected_revision=old.revision,
        )
    assert store.lifecycle_snapshot("worker") == current


def test_single_flight_deduplicates_concurrent_refreshes():
    started = threading.Event()
    release = threading.Event()
    calls = 0
    lock = threading.Lock()

    def operation(_cancelled: threading.Event) -> str:
        nonlocal calls
        with lock:
            calls += 1
        started.set()
        assert release.wait(1)
        return "verified"

    with SingleFlightReattestor[str](max_workers=2) as coordinator:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                coordinator.run,
                "worker",
                1,
                operation,
                timeout_seconds=1,
            )
            assert started.wait(1)
            second = executor.submit(
                coordinator.run,
                "worker",
                1,
                operation,
                timeout_seconds=1,
            )
            release.set()
            assert first.result() == second.result() == "verified"
    assert calls == 1


def test_single_flight_terminal_cancellation_and_timeout_are_bounded():
    started = threading.Event()

    def waits_for_cancel(cancelled: threading.Event) -> str:
        started.set()
        cancelled.wait(1)
        return "late"

    with SingleFlightReattestor[str](max_workers=1) as coordinator:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(
                coordinator.run,
                "worker",
                1,
                waits_for_cancel,
                timeout_seconds=1,
            )
            assert started.wait(1)
            assert coordinator.cancel("worker") is True
            with pytest.raises(LifecycleError, match="cancelled"):
                pending.result()

        start = time.monotonic()
        with pytest.raises(LifecycleError, match="timed out"):
            coordinator.run(
                "other-worker",
                1,
                waits_for_cancel,
                timeout_seconds=0.02,
            )
        assert time.monotonic() - start < 0.5


def test_worker_removal_cancels_refresh_and_requires_new_generation(tmp_path: Path):
    clock = MutableClock()
    store = _store(tmp_path, clock)
    coordinator = SingleFlightReattestor[str](max_workers=1)
    runtime = ConfidentialRuntime(
        store,
        Ledger(),
        _policy(),
        reattestor=coordinator,  # type: ignore[arg-type]
        config=RuntimeConfig(production_mode=True, admission_enabled=False),
    )
    started = threading.Event()

    def refresh(cancelled: threading.Event) -> str:
        started.set()
        cancelled.wait(1)
        return "late"

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(
                coordinator.run,
                "worker",
                1,
                refresh,
                timeout_seconds=1,
            )
            assert started.wait(1)
            retired = runtime.retire_worker("worker", removed=True)
            assert retired.state is WorkerLifecycleState.RETIRED
            with pytest.raises(LifecycleError, match="cancelled"):
                pending.result()

        reenrolled = runtime.reenroll_worker("worker")
        assert reenrolled.state is WorkerLifecycleState.PENDING
        assert reenrolled.generation == retired.generation + 1
    finally:
        coordinator.close()


@pytest.mark.parametrize("timeout", [True, float("nan"), float("inf"), 0])
def test_single_flight_rejects_invalid_timeouts(timeout: object):
    with SingleFlightReattestor[str](max_workers=1) as coordinator:
        with pytest.raises(LifecycleError, match="timeout"):
            coordinator.run(
                "worker",
                1,
                lambda _cancelled: "unused",
                timeout_seconds=timeout,  # type: ignore[arg-type]
            )
