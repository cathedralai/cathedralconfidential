"""Explicit worker-attestation lifecycle and single-flight refresh control."""

from __future__ import annotations

import hashlib
import math
import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Callable, Generic, TypeVar


class LifecycleError(RuntimeError):
    """Raised when a lifecycle transition or refresh invariant would be violated."""


class WorkerLifecycleState(str, Enum):
    PENDING = "pending"
    ATTESTED = "attested"
    STALE = "stale"
    FAILED = "failed"
    RETIRING = "retiring"
    RETIRED = "retired"
    REVOKED = "revoked"


class LifecycleReason(str, Enum):
    ENROLLED = "enrolled"
    ENDPOINT_CHANGED = "endpoint_changed"
    REENROLLED = "reenrolled"
    ATTESTATION_VERIFIED = "attestation_verified"
    REFRESH_SCHEDULED = "refresh_scheduled"
    REFRESH_RETRY = "refresh_retry"
    EVIDENCE_EXPIRED = "evidence_expired"
    VERIFICATION_FAILED = "verification_failed"
    RETRY_EXHAUSTED = "retry_exhausted"
    POLICY_REVOKED = "policy_revoked"
    IDENTITY_CONFLICT = "identity_conflict"
    OPERATOR_RETIRING = "operator_retiring"
    OPERATOR_RETIRED = "operator_retired"
    WORKER_REMOVED = "worker_removed"
    REFRESH_CANCELLED = "refresh_cancelled"
    BACKFILL_PENDING = "backfill_pending"
    BACKFILL_STALE = "backfill_stale"


TERMINAL_STATES = frozenset(
    {WorkerLifecycleState.RETIRED, WorkerLifecycleState.REVOKED}
)
NETWORK_ELIGIBLE_STATES = frozenset(
    {
        WorkerLifecycleState.PENDING,
        WorkerLifecycleState.ATTESTED,
        WorkerLifecycleState.STALE,
    }
)

# Self-transitions are deliberate audit events: a successful refresh advances
# attested evidence, while a retry event advances bounded retry metadata.
ALLOWED_TRANSITIONS = {
    WorkerLifecycleState.PENDING: frozenset(
        {
            WorkerLifecycleState.PENDING,
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.FAILED,
            WorkerLifecycleState.RETIRING,
            WorkerLifecycleState.REVOKED,
        }
    ),
    WorkerLifecycleState.ATTESTED: frozenset(
        {
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.STALE,
            WorkerLifecycleState.FAILED,
            WorkerLifecycleState.RETIRING,
            WorkerLifecycleState.REVOKED,
        }
    ),
    WorkerLifecycleState.STALE: frozenset(
        {
            WorkerLifecycleState.STALE,
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.FAILED,
            WorkerLifecycleState.RETIRING,
            WorkerLifecycleState.REVOKED,
        }
    ),
    WorkerLifecycleState.FAILED: frozenset(
        {
            WorkerLifecycleState.FAILED,
            WorkerLifecycleState.RETIRING,
            WorkerLifecycleState.REVOKED,
        }
    ),
    WorkerLifecycleState.RETIRING: frozenset(
        {WorkerLifecycleState.RETIRING, WorkerLifecycleState.RETIRED, WorkerLifecycleState.REVOKED}
    ),
    WorkerLifecycleState.RETIRED: frozenset({WorkerLifecycleState.RETIRED}),
    WorkerLifecycleState.REVOKED: frozenset({WorkerLifecycleState.REVOKED}),
}

REASON_TARGETS = {
    LifecycleReason.ATTESTATION_VERIFIED: frozenset({WorkerLifecycleState.ATTESTED}),
    LifecycleReason.REFRESH_SCHEDULED: frozenset(
        {
            WorkerLifecycleState.PENDING,
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.STALE,
        }
    ),
    LifecycleReason.REFRESH_RETRY: frozenset(
        {
            WorkerLifecycleState.PENDING,
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.STALE,
        }
    ),
    LifecycleReason.REFRESH_CANCELLED: frozenset(
        {
            WorkerLifecycleState.PENDING,
            WorkerLifecycleState.ATTESTED,
            WorkerLifecycleState.STALE,
        }
    ),
    LifecycleReason.EVIDENCE_EXPIRED: frozenset({WorkerLifecycleState.STALE}),
    LifecycleReason.VERIFICATION_FAILED: frozenset({WorkerLifecycleState.FAILED}),
    LifecycleReason.RETRY_EXHAUSTED: frozenset({WorkerLifecycleState.FAILED}),
    LifecycleReason.POLICY_REVOKED: frozenset({WorkerLifecycleState.REVOKED}),
    LifecycleReason.IDENTITY_CONFLICT: frozenset({WorkerLifecycleState.REVOKED}),
    LifecycleReason.OPERATOR_RETIRING: frozenset({WorkerLifecycleState.RETIRING}),
    LifecycleReason.OPERATOR_RETIRED: frozenset({WorkerLifecycleState.RETIRED}),
    LifecycleReason.WORKER_REMOVED: frozenset({WorkerLifecycleState.RETIRED}),
}

SNAPSHOT_REASON_TARGETS = {
    **REASON_TARGETS,
    LifecycleReason.ENROLLED: frozenset({WorkerLifecycleState.PENDING}),
    LifecycleReason.ENDPOINT_CHANGED: frozenset({WorkerLifecycleState.PENDING}),
    LifecycleReason.REENROLLED: frozenset({WorkerLifecycleState.PENDING}),
    LifecycleReason.BACKFILL_PENDING: frozenset({WorkerLifecycleState.PENDING}),
    LifecycleReason.BACKFILL_STALE: frozenset({WorkerLifecycleState.STALE}),
}


def require_transition(
    current: WorkerLifecycleState,
    target: WorkerLifecycleState,
) -> None:
    if not isinstance(current, WorkerLifecycleState) or not isinstance(
        target, WorkerLifecycleState
    ):
        raise LifecycleError("worker lifecycle state is invalid")
    if target not in ALLOWED_TRANSITIONS[current]:
        raise LifecycleError(
            f"illegal worker lifecycle transition {current.value} -> {target.value}"
        )


def require_transition_reason(
    target: WorkerLifecycleState,
    reason: LifecycleReason,
) -> None:
    if target not in REASON_TARGETS.get(reason, frozenset()):
        raise LifecycleError(
            f"worker lifecycle reason {reason.value} is invalid for {target.value}"
        )


def require_snapshot_reason(
    state: WorkerLifecycleState,
    reason: LifecycleReason,
) -> None:
    if state not in SNAPSHOT_REASON_TARGETS.get(reason, frozenset()):
        raise LifecycleError(
            f"worker lifecycle reason {reason.value} is invalid for {state.value}"
        )


def canonical_utc(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise LifecycleError("worker lifecycle time must be UTC")
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise LifecycleError("persisted worker lifecycle time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise LifecycleError("persisted worker lifecycle time is invalid") from exc
    return parsed


@dataclass(frozen=True)
class LifecycleSnapshot:
    hotkey: str
    state: WorkerLifecycleState
    generation: int
    revision: int
    event_id: int
    reason: LifecycleReason
    state_changed_at: datetime
    evidence_verified_at: datetime | None = None
    evidence_expires_at: datetime | None = None
    measurement: str | None = None
    evidence_digest: str | None = None
    policy_digest: str | None = None
    policy_registry_release: int | None = None
    policy_registry_digest: str | None = None
    retry_count: int = 0
    next_retry_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.hotkey, str)
            or not self.hotkey
            or len(self.hotkey) > 512
            or not isinstance(self.state, WorkerLifecycleState)
            or not isinstance(self.reason, LifecycleReason)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= 2**63 - 1
                for value in (self.generation, self.revision, self.event_id)
            )
            or isinstance(self.retry_count, bool)
            or not isinstance(self.retry_count, int)
            or self.retry_count < 0
        ):
            raise LifecycleError("worker lifecycle snapshot is invalid")
        canonical_utc(self.state_changed_at)
        require_snapshot_reason(self.state, self.reason)
        for value in (
            self.evidence_verified_at,
            self.evidence_expires_at,
            self.next_retry_at,
        ):
            if value is not None:
                canonical_utc(value)
        if (
            self.evidence_verified_at is not None
            and self.evidence_expires_at is not None
            and self.evidence_expires_at <= self.evidence_verified_at
        ):
            raise LifecycleError("worker lifecycle evidence window is invalid")
        if self.state is WorkerLifecycleState.ATTESTED and (
            self.evidence_verified_at is None
            or self.evidence_expires_at is None
            or self.evidence_verified_at > self.state_changed_at
            or self.evidence_expires_at <= self.state_changed_at
            or not isinstance(self.measurement, str)
            or not self.measurement
            or not isinstance(self.evidence_digest, str)
            or not self.evidence_digest
            or not isinstance(self.policy_digest, str)
            or not self.policy_digest
        ):
            raise LifecycleError("attested worker lifecycle snapshot is incomplete")
        if (self.policy_registry_release is None) != (
            self.policy_registry_digest is None
        ):
            raise LifecycleError("worker lifecycle policy registry reference is invalid")
        if self.policy_registry_release is not None and (
            isinstance(self.policy_registry_release, bool)
            or not isinstance(self.policy_registry_release, int)
            or not 0 < self.policy_registry_release <= 2**63 - 1
            or not isinstance(self.policy_registry_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.policy_registry_digest)
            is None
        ):
            raise LifecycleError("worker lifecycle policy registry reference is invalid")

    def eligible_at(self, when: datetime) -> bool:
        canonical_utc(when)
        return (
            self.state is WorkerLifecycleState.ATTESTED
            and self.evidence_expires_at is not None
            and when < self.evidence_expires_at
        )

    def public_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "reason": self.reason.value,
            "generation": self.generation,
            "state_changed_at": canonical_utc(self.state_changed_at),
            "evidence_verified_at": (
                canonical_utc(self.evidence_verified_at)
                if self.evidence_verified_at is not None
                else None
            ),
            "evidence_expires_at": (
                canonical_utc(self.evidence_expires_at)
                if self.evidence_expires_at is not None
                else None
            ),
        }

    def operator_dict(self) -> dict[str, object]:
        result = self.public_dict()
        result.update(
            {
                "revision": self.revision,
                "event_id": self.event_id,
                "measurement": self.measurement,
                "evidence_digest": self.evidence_digest,
                "policy_digest": self.policy_digest,
                "policy_registry_release": self.policy_registry_release,
                "policy_registry_digest": self.policy_registry_digest,
                "retry_count": self.retry_count,
                "next_retry_at": (
                    canonical_utc(self.next_retry_at)
                    if self.next_retry_at is not None
                    else None
                ),
            }
        )
        return result


def retry_delay_seconds(
    hotkey: str,
    generation: int,
    attempt: int,
    *,
    base_seconds: int,
    maximum_seconds: int,
    jitter_seconds: int,
) -> int:
    if (
        not isinstance(hotkey, str)
        or not hotkey
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation <= 0
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt <= 0
        or isinstance(base_seconds, bool)
        or not isinstance(base_seconds, int)
        or isinstance(maximum_seconds, bool)
        or not isinstance(maximum_seconds, int)
        or isinstance(jitter_seconds, bool)
        or not isinstance(jitter_seconds, int)
        or not 1 <= base_seconds <= maximum_seconds <= 86400
        or not 0 <= jitter_seconds <= maximum_seconds
    ):
        raise LifecycleError("worker lifecycle retry policy is invalid")
    exponential = min(maximum_seconds, base_seconds * (2 ** min(attempt - 1, 30)))
    material = f"{hotkey}\0{generation}\0{attempt}".encode("utf-8")
    jitter = (
        int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
        % (jitter_seconds + 1)
        if jitter_seconds
        else 0
    )
    return min(maximum_seconds, exponential + jitter)


T = TypeVar("T")


@dataclass
class _Flight(Generic[T]):
    generation: int
    cancel: threading.Event
    future: Future[T]


class SingleFlightReattestor(Generic[T]):
    """Deduplicate refreshes and discard results cancelled by terminal state."""

    def __init__(self, *, max_workers: int = 8) -> None:
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 64:
            raise ValueError("max_workers must be between 1 and 64")
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._lock = threading.RLock()
        self._flights: dict[str, _Flight[T]] = {}

    def run(
        self,
        hotkey: str,
        generation: int,
        operation: Callable[[threading.Event], T],
        *,
        timeout_seconds: float,
    ) -> T:
        if not isinstance(hotkey, str) or not hotkey:
            raise LifecycleError("refresh hotkey is invalid")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise LifecycleError("refresh generation is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise LifecycleError("refresh timeout must be positive")
        with self._lock:
            flight = self._flights.get(hotkey)
            if flight is not None and not flight.future.done():
                if flight.generation != generation:
                    flight.cancel.set()
                    raise LifecycleError("worker generation changed during refresh")
            else:
                cancel = threading.Event()
                future = self._executor.submit(self._invoke, cancel, operation)
                flight = _Flight(generation, cancel, future)
                self._flights[hotkey] = flight
                future.add_done_callback(
                    lambda completed, key=hotkey: self._completed(key, completed)
                )
        try:
            return flight.future.result(timeout=float(timeout_seconds))
        except TimeoutError as exc:
            flight.cancel.set()
            raise LifecycleError("worker re-attestation timed out") from exc

    @staticmethod
    def _invoke(cancel: threading.Event, operation: Callable[[threading.Event], T]) -> T:
        if cancel.is_set():
            raise LifecycleError("worker re-attestation was cancelled")
        result = operation(cancel)
        if cancel.is_set():
            raise LifecycleError("worker re-attestation was cancelled")
        return result

    def _completed(self, hotkey: str, future: Future[T]) -> None:
        with self._lock:
            current = self._flights.get(hotkey)
            if current is not None and current.future is future:
                self._flights.pop(hotkey, None)

    def cancel(self, hotkey: str) -> bool:
        with self._lock:
            flight = self._flights.get(hotkey)
            if flight is None or flight.future.done():
                return False
            flight.cancel.set()
            flight.future.cancel()
            return True

    def active_count(self) -> int:
        with self._lock:
            return sum(not flight.future.done() for flight in self._flights.values())

    def close(self) -> None:
        with self._lock:
            for flight in self._flights.values():
                flight.cancel.set()
        self._executor.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> SingleFlightReattestor[T]:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
