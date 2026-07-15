"""Confidential CPU-TDX and audit-only composite-GPU report runtime.

This module only freezes and optionally publishes Cathedral confidential-compute
reports. The existing validator remains the sole owner of score composition,
signing, and chain publication.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import threading
import urllib.parse
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    SCORE_ELIGIBILITY_POLICY,
    WORK_DISPATCH_POLICY,
    AssuranceClaims,
    AssuranceDimension,
    ClaimStatus,
    ReasonCategory,
    evaluated_claim,
    sha256_digest,
    with_verified_channel,
)
from cathedral.common import (
    Attested,
    ChannelBinding,
    Evidence,
    EvidenceKind,
    MAX_EVIDENCE_RESPONSE_BODY,
    MAX_GPU_EVIDENCE_CONCURRENCY,
    Policy,
    Tier,
    issue_nonce,
    is_globally_routable,
)
from cathedral.enroll import RegistryStore
from cathedral.lanes.sat import SatLane
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.lifecycle import (
    NETWORK_ELIGIBLE_STATES,
    LifecycleError,
    LifecycleReason,
    LifecycleSnapshot,
    SingleFlightReattestor,
    WorkerLifecycleState,
)
from cathedral.poster import Poster
from cathedral.remote import RemoteMiner
from cathedral.receipt import ReceiptIssuer
from cathedral.verify import verify

MAX_BEARER_TOKEN_LENGTH = 4096
SAT_WORK_POLICY_DIGEST = sha256_digest(b"cathedral-sat-work-verification-policy-v1")


class RuntimeError(Exception):
    """Raised when a confidential runtime invariant fails."""


class MinerClient(Protocol):
    def collect_evidence(self, nonce: bytes) -> Evidence: ...

    def collect_evidence_bundle(self, nonce: bytes) -> tuple[Evidence, ...]: ...

    def confirm_channel_binding(self, evidence: Evidence) -> ChannelBinding: ...

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate: ...


@dataclass(frozen=True)
class MinerTarget:
    hotkey: str
    endpoint_url: str
    bearer_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RuntimeConfig:
    miner_timeout_seconds: float = 10.0
    miner_attempts: int = 2
    max_workers: int = 8
    production_mode: bool = True
    allow_insecure_http_for_tests: bool = False
    reattestation_failures_before_failed: int = 3
    reattestation_retry_base_seconds: int = 5
    reattestation_retry_maximum_seconds: int = 300
    reattestation_retry_jitter_seconds: int = 5
    expected_tier: Tier = Tier.CC_CPU_TDX

    def __post_init__(self) -> None:
        timeout = self.miner_timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("miner_timeout_seconds must be positive and finite")
        if (
            isinstance(self.miner_attempts, bool)
            or not isinstance(self.miner_attempts, int)
            or self.miner_attempts <= 0
        ):
            raise ValueError("miner_attempts must be a positive integer")
        if (
            isinstance(self.max_workers, bool)
            or not isinstance(self.max_workers, int)
            or not 1 <= self.max_workers <= 64
        ):
            raise ValueError("max_workers must be between 1 and 64")
        if not isinstance(self.production_mode, bool):
            raise ValueError("production_mode must be a boolean")
        if not isinstance(self.allow_insecure_http_for_tests, bool):
            raise ValueError("allow_insecure_http_for_tests must be a boolean")
        if self.production_mode and self.allow_insecure_http_for_tests:
            raise ValueError("insecure HTTP is unavailable in production mode")
        if self.expected_tier not in {Tier.CC_CPU_TDX, Tier.CC_GPU}:
            raise ValueError("runtime expected tier must be CPU TDX or GPU composite")
        if (
            isinstance(self.reattestation_failures_before_failed, bool)
            or not isinstance(self.reattestation_failures_before_failed, int)
            or not 1 <= self.reattestation_failures_before_failed <= 32
        ):
            raise ValueError("reattestation failure bound must be between 1 and 32")
        if (
            isinstance(self.reattestation_retry_base_seconds, bool)
            or not isinstance(self.reattestation_retry_base_seconds, int)
            or isinstance(self.reattestation_retry_maximum_seconds, bool)
            or not isinstance(self.reattestation_retry_maximum_seconds, int)
            or not 1
            <= self.reattestation_retry_base_seconds
            <= self.reattestation_retry_maximum_seconds
            <= 86400
            or isinstance(self.reattestation_retry_jitter_seconds, bool)
            or not isinstance(self.reattestation_retry_jitter_seconds, int)
            or not 0
            <= self.reattestation_retry_jitter_seconds
            <= self.reattestation_retry_maximum_seconds
        ):
            raise ValueError("reattestation retry policy is invalid")


@dataclass(frozen=True)
class MinerOutcome:
    hotkey: str
    endpoint_url: str
    status: str
    admitted: bool = False
    challenge_id: str | None = None
    work_units: float = 0.0
    score: float = 0.0
    error: str | None = None
    error_category: str | None = None
    assurance: AssuranceClaims | None = None
    component_audit: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.component_audit is not None:
            object.__setattr__(
                self,
                "component_audit",
                MappingProxyType(dict(self.component_audit)),
            )


@dataclass(frozen=True)
class EpochRun:
    epoch_id: int
    source_epoch: int
    status: str
    outcomes: tuple[MinerOutcome, ...]
    scores: Mapping[str, float]
    published: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "scores", MappingProxyType(dict(self.scores)))


@dataclass(frozen=True)
class _AttestationResult:
    target: MinerTarget
    endpoint: str
    attested: Attested | None = None
    evidence_digest: str | None = None
    client: MinerClient | None = None
    error: str | None = None
    error_category: str | None = None
    component_audit: Mapping[str, object] | None = None
    gpu_component: object | None = field(default=None, repr=False)
    lifecycle_generation: int | None = None
    lifecycle_revision: int | None = None


@dataclass(frozen=True)
class _CanaryResult:
    outcome: MinerOutcome
    attestation: _AttestationResult


Verifier = Callable[[Evidence, bytes, Policy], Attested | None]
NonceFactory = Callable[[], bytes]
TokenProvider = Callable[[str], str | None]
RemoteFactory = Callable[..., MinerClient]


class ConfidentialRuntime:
    """Run one fresh requested-tier attestation and canonical SAT job per worker."""

    def __init__(
        self,
        registry: RegistryStore,
        ledger: Ledger,
        policy: Policy,
        poster: Poster | None = None,
        *,
        token_provider: TokenProvider | None = None,
        verifier: Verifier = verify,
        nonce_factory: NonceFactory = issue_nonce,
        remote_factory: RemoteFactory = RemoteMiner,
        config: RuntimeConfig | None = None,
        receipt_issuer: ReceiptIssuer | None = None,
        reattestor: SingleFlightReattestor[_AttestationResult] | None = None,
        gpu_profile=None,
        gpu_verifier=None,
        gpu_identity_registry=None,
    ) -> None:
        self.registry = registry
        self.ledger = ledger
        self.policy = policy
        self.poster = poster
        self.token_provider = token_provider or (lambda _hotkey: None)
        self.verifier = verifier
        self.nonce_factory = nonce_factory
        self.remote_factory = remote_factory
        self.config = config or RuntimeConfig()
        gpu_configuration = (gpu_profile, gpu_verifier, gpu_identity_registry)
        if self.config.expected_tier is Tier.CC_GPU and any(
            item is None for item in gpu_configuration
        ):
            raise ValueError(
                "GPU runtime requires profile, verifier, and durable identity registry"
            )
        if self.config.expected_tier is Tier.CC_CPU_TDX and any(
            item is not None for item in gpu_configuration
        ):
            raise ValueError("CPU runtime cannot carry GPU verifier configuration")
        if self.config.expected_tier is Tier.CC_GPU:
            from cathedral.gpu import (
                ExternalGpuVerifier,
                GpuIdentityRegistry,
                GpuProfile,
            )

            if not isinstance(gpu_profile, GpuProfile) or not isinstance(
                gpu_identity_registry, GpuIdentityRegistry
            ):
                raise ValueError("GPU runtime profile or identity registry is invalid")
            if self.config.production_mode:
                if not gpu_profile.production_ready_for(self.policy):
                    raise ValueError(
                        "production GPU runtime requires a live profile from its CPU policy registry"
                    )
                if not gpu_identity_registry.production_ready:
                    raise ValueError(
                        "production GPU runtime requires a protected identity registry"
                    )
                if not isinstance(gpu_verifier, ExternalGpuVerifier):
                    raise ValueError("production GPU runtime requires the pinned external verifier")
                if not gpu_verifier.production_ready:
                    raise ValueError("production GPU runtime requires a static verifier executable")
                gpu_verifier.preflight(gpu_profile)
        self.gpu_profile = gpu_profile
        self.gpu_verifier = gpu_verifier
        self.gpu_identity_registry = gpu_identity_registry
        if self.config.expected_tier is Tier.CC_GPU and receipt_issuer is not None:
            raise ValueError(
                "GPU receipt issuance is disabled until a composite receipt schema is active"
            )
        self.receipt_issuer = receipt_issuer
        attestation_workers = (
            min(self.config.max_workers, MAX_GPU_EVIDENCE_CONCURRENCY)
            if self.config.expected_tier is Tier.CC_GPU
            else self.config.max_workers
        )
        self._attestation_workers = attestation_workers
        self._gpu_evidence_slots = threading.BoundedSemaphore(MAX_GPU_EVIDENCE_CONCURRENCY)
        self.reattestor = reattestor or SingleFlightReattestor(max_workers=attestation_workers)
        self._owns_reattestor = reattestor is None
        self._run_lock = threading.Lock()

    def _require_live_gpu_profile(self) -> None:
        if self.config.expected_tier is not Tier.CC_GPU or not self.config.production_mode:
            return
        from cathedral.gpu import GpuProfile

        if not isinstance(
            self.gpu_profile, GpuProfile
        ) or not self.gpu_profile.production_ready_for(self.policy):
            raise RuntimeError(
                "production GPU profile is expired or no longer matches the CPU policy"
            )

    def check_canary(self, canary: MinerTarget) -> MinerOutcome:
        self._require_live_gpu_profile()
        return self._check_canary_result(canary).outcome

    def audit_attestation(self, target: MinerTarget) -> MinerOutcome:
        """Verify fresh evidence and its live channel without dispatch or scoring."""

        self._require_live_gpu_profile()
        checked, endpoint = self._validate_target(target)
        result = self._collect_attestation(checked, endpoint)
        if result.attested is None:
            return MinerOutcome(
                hotkey=checked.hotkey,
                endpoint_url=endpoint,
                status="attestation_failed",
                error=result.error or "rejected",
                error_category=result.error_category or "attestation_rejected",
            )
        return MinerOutcome(
            hotkey=checked.hotkey,
            endpoint_url=endpoint,
            status="attestation_verified",
            assurance=result.attested.assurance,
            component_audit=result.component_audit,
        )

    def _check_canary_result(self, canary: MinerTarget) -> _CanaryResult:
        target, endpoint = self._validate_target(canary)
        result = self._collect_attestation(target, endpoint)
        if result.attested is None or result.client is None:
            raise RuntimeError(f"canary attestation failed: {result.error or 'rejected'}")
        if not WORK_DISPATCH_POLICY.allows(result.attested.assurance):
            raise RuntimeError("canary lacks a verified protected channel")
        if self.config.expected_tier is Tier.CC_GPU:
            from cathedral.gpu import (
                GpuAttestationError,
                GpuComponentVerdict,
                GpuIdentityRegistry,
            )

            if not isinstance(self.gpu_identity_registry, GpuIdentityRegistry) or not isinstance(
                result.gpu_component, GpuComponentVerdict
            ):
                raise RuntimeError("GPU canary is missing its identity component")
            try:
                self.gpu_identity_registry.assert_unclaimed(result.gpu_component)
            except GpuAttestationError as exc:
                if exc.category != "identity_conflict":
                    raise
                raise RuntimeError("canary GPU identity is already enrolled") from exc

        self._require_live_gpu_profile()
        lane = SatLane(
            namespace=f"canary:{target.hotkey}",
            gpu_profile=self.gpu_profile,
            gpu_policy=self.policy,
        )
        if not lane.qualify(result.attested):
            raise RuntimeError("canary hardware tier is not enabled for SAT scoring")
        item = lane.dispatch(target.hotkey, budget=1)
        if not isinstance(item, SatWorkItem):
            raise RuntimeError("canary did not receive canonical SAT work")
        certificate, error = self._request_sat(result.client, item)
        accepted = lane.verify(item, certificate) if certificate is not None else None
        if accepted is None:
            raise RuntimeError(f"canary SAT failed: {error or 'invalid certificate'}")
        assurance = _work_assurance(result.attested, item, certificate, passed=True)
        if not SCORE_ELIGIBILITY_POLICY.allows(assurance):
            raise RuntimeError("canary claims do not satisfy score eligibility policy")
        self._require_live_gpu_profile()
        units = lane.score(target.hotkey, [accepted])
        if units <= 0:
            raise RuntimeError("canary SAT produced no verified work")
        return _CanaryResult(
            outcome=MinerOutcome(
                hotkey=target.hotkey,
                endpoint_url=endpoint,
                status="canary_verified",
                admitted=True,
                challenge_id=item.challenge_id,
                work_units=units,
                assurance=assurance,
            ),
            attestation=result,
        )

    def _reserve_gpu_canary(self, canary: _CanaryResult):
        if self.config.expected_tier is not Tier.CC_GPU:
            return None
        from cathedral.gpu import (
            GpuAttestationError,
            GpuComponentVerdict,
            GpuIdentityRegistry,
        )

        component = canary.attestation.gpu_component
        if not isinstance(self.gpu_identity_registry, GpuIdentityRegistry) or not isinstance(
            component, GpuComponentVerdict
        ):
            raise RuntimeError("GPU canary is missing its identity component")
        try:
            return self.gpu_identity_registry.begin_exclusive_reservation(
                canary.attestation.target.hotkey,
                component,
            )
        except GpuAttestationError as exc:
            if exc.category != "identity_conflict":
                raise
            raise RuntimeError("canary GPU identity is already enrolled") from exc

    def run_epoch(
        self,
        source_epoch: int,
        canary: MinerTarget,
        *,
        publish: bool = False,
    ) -> EpochRun:
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("an epoch run is already in progress")
        try:
            return self._run_epoch_once(source_epoch, canary, publish=publish)
        finally:
            self._run_lock.release()

    def _run_epoch_once(
        self,
        source_epoch: int,
        canary: MinerTarget,
        *,
        publish: bool = False,
    ) -> EpochRun:
        if not isinstance(publish, bool):
            raise ValueError("publish must be a boolean")
        self._require_live_gpu_profile()
        canary_target, canary_endpoint = self._validate_target(canary)

        lifecycle_measurements = self.policy.allowed_measurements
        if self.config.expected_tier is Tier.CC_GPU:
            from cathedral.gpu import gpu_lifecycle_measurements

            lifecycle_measurements = gpu_lifecycle_measurements(self.policy, self.gpu_profile)
        revoked = self.registry.apply_lifecycle_policy(
            lifecycle_measurements,
            policy_registry_release=self.policy.registry_release,
            policy_registry_digest=self.policy.registry_digest,
        )
        for snapshot in revoked:
            self.reattestor.cancel(snapshot.hotkey)
        enrollments = self.registry.enrollments()
        if any(item.hotkey == canary_target.hotkey for item in enrollments):
            raise RuntimeError("canary identity must be dedicated and not enrolled")
        refresh_due = {
            snapshot.hotkey
            for snapshot in self.registry.due_refreshes(
                refresh_ahead_seconds=self.registry.verification_ttl_seconds
            )
        }
        targets: list[MinerTarget] = []
        lifecycle_outcomes: dict[str, MinerOutcome] = {}
        for enrollment in enrollments:
            snapshot = self.registry.lifecycle_snapshot(enrollment.hotkey)
            if snapshot.state not in NETWORK_ELIGIBLE_STATES:
                lifecycle_outcomes[enrollment.hotkey] = MinerOutcome(
                    enrollment.hotkey,
                    enrollment.endpoint_url,
                    snapshot.state.value,
                    error=f"worker lifecycle is {snapshot.state.value}",
                )
                self.reattestor.cancel(enrollment.hotkey)
                continue
            if enrollment.hotkey not in refresh_due:
                lifecycle_outcomes[enrollment.hotkey] = MinerOutcome(
                    enrollment.hotkey,
                    enrollment.endpoint_url,
                    "refresh_scheduled",
                    error="worker re-attestation retry is not due",
                )
                continue
            targets.append(
                MinerTarget(
                    enrollment.hotkey,
                    enrollment.endpoint_url,
                    self.token_provider(enrollment.hotkey),
                )
            )
        self._validate_required_auth((canary_target, *targets))
        prepared, outcomes, enrolled_endpoints = self._prepare_targets(targets)
        outcomes = {**lifecycle_outcomes, **outcomes}
        if canary_endpoint in enrolled_endpoints:
            raise RuntimeError("canary endpoint must be dedicated and not enrolled")

        canary_result = self._check_canary_result(canary_target)
        canary_reservation = self._reserve_gpu_canary(canary_result)
        try:
            attested = self._attest_targets(prepared, outcomes)
            canary_attested = canary_result.attestation.attested
            assert canary_attested is not None
            if any(
                result.attested is not None and result.attested.chip_id == canary_attested.chip_id
                for result in attested
            ):
                raise RuntimeError(
                    "an enrolled miner shares the dedicated canary TDX chip or "
                    "composite hardware identity"
                )
            if self.config.expected_tier is Tier.CC_GPU:
                from cathedral.gpu import GpuComponentVerdict

                canary_component = canary_result.attestation.gpu_component
                if not isinstance(canary_component, GpuComponentVerdict):
                    raise RuntimeError("GPU canary is missing its identity component")
                if any(
                    isinstance(result.gpu_component, GpuComponentVerdict)
                    and bool(canary_component.identity_set & result.gpu_component.identity_set)
                    for result in attested
                ):
                    raise RuntimeError("an enrolled miner shares the dedicated canary GPU identity")

            epoch_id = self.ledger.begin_epoch(
                source_epoch,
                policy_registry_release=self.policy.registry_release,
                policy_registry_digest=self.policy.registry_digest,
            )
            try:
                admitted = self._admit_unique_chips(epoch_id, attested, outcomes)
                self._run_sat(epoch_id, source_epoch, admitted, outcomes)
                self._require_live_gpu_profile()

                for enrollment in enrollments:
                    self.ledger.add_lifecycle_snapshot(
                        epoch_id,
                        self.registry.lifecycle_snapshot(enrollment.hotkey),
                    )

                all_hotkeys = {enrollment.hotkey for enrollment in enrollments}
                self._require_live_gpu_profile()
                score_authority_valid_until = None
                if self.config.expected_tier is Tier.CC_GPU and self.config.production_mode:
                    score_authority_valid_until = self.gpu_profile.registry_valid_until
                scores = self.ledger.complete_epoch(
                    epoch_id,
                    all_hotkeys,
                    score_authority_valid_until=score_authority_valid_until,
                )
                outcomes = {
                    hotkey: MinerOutcome(
                        hotkey=outcome.hotkey,
                        endpoint_url=outcome.endpoint_url,
                        status=outcome.status,
                        admitted=outcome.admitted,
                        challenge_id=outcome.challenge_id,
                        work_units=outcome.work_units,
                        score=scores.get(hotkey, 0.0),
                        error=outcome.error,
                        error_category=outcome.error_category,
                        assurance=outcome.assurance,
                        component_audit=outcome.component_audit,
                    )
                    for hotkey, outcome in outcomes.items()
                }
                if publish:
                    self.publish_completed(epoch_id)
                row = self.ledger.get_epoch(epoch_id)
                assert row is not None
                return EpochRun(
                    epoch_id=epoch_id,
                    source_epoch=source_epoch,
                    status=str(row["status"]),
                    outcomes=tuple(outcomes[key] for key in sorted(outcomes)),
                    scores=scores,
                    published=row["status"] == "published",
                )
            except BaseException:
                row = self.ledger.get_epoch(epoch_id)
                if row is not None and row["status"] == "running":
                    self.ledger.abort_epoch(epoch_id)
                raise
        finally:
            if canary_reservation is not None:
                self.gpu_identity_registry.rollback_claim(canary_reservation)

    def publish_completed(self, epoch_id: int) -> Mapping[str, object]:
        if self.poster is None:
            raise RuntimeError("publisher is not configured")
        blocking = self.ledger.blocking_epoch()
        if blocking is None or blocking["status"] != "complete" or blocking["epoch_id"] != epoch_id:
            raise RuntimeError("epoch_id must identify the exact completed blocking epoch")
        acknowledgement = self.ledger.post_and_mark_published(epoch_id, self.poster)
        return MappingProxyType(dict(acknowledgement))

    def status(self) -> Mapping[str, object]:
        blocking = self.ledger.blocking_epoch()
        return MappingProxyType(
            {"blocking_epoch": dict(blocking) if blocking is not None else None}
        )

    def retire_worker(self, hotkey: str, *, removed: bool = False) -> LifecycleSnapshot:
        current = self.registry.retire_lifecycle(hotkey, removed=removed)
        self.reattestor.cancel(hotkey)
        return current

    def reenroll_worker(self, hotkey: str) -> LifecycleSnapshot:
        self.reattestor.cancel(hotkey)
        return self.registry.reenroll_lifecycle(hotkey)

    def close(self) -> None:
        if self._owns_reattestor:
            self.reattestor.close()
            self._owns_reattestor = False

    def __del__(self) -> None:  # pragma: no cover - interpreter cleanup fallback
        try:
            self.close()
        except Exception:
            pass

    def abort_running(self) -> int:
        blocking = self.ledger.blocking_epoch()
        if blocking is None or blocking["status"] != "running":
            raise RuntimeError("there is no running epoch to abort")
        epoch_id = int(blocking["epoch_id"])
        self.ledger.abort_epoch(epoch_id)
        return epoch_id

    def abandon_completed(self, epoch_id: int, reason: str) -> int:
        """Recovery path for a completed report that can never be published.

        Use when a 'complete' epoch's frozen report has aged past what the
        downstream ingest service accepts for a first publish (retry-publish
        can only resend identical bytes, so that report is permanently stuck).
        Requires a nonempty operator reason; see
        ``Ledger.abandon_completed_epoch`` for the full audit and payability
        guarantees.
        """
        blocking = self.ledger.blocking_epoch()
        if blocking is None or blocking["status"] != "complete" or blocking["epoch_id"] != epoch_id:
            raise RuntimeError("epoch_id must identify the exact completed blocking epoch")
        self.ledger.abandon_completed_epoch(epoch_id, reason)
        return epoch_id

    def _prepare_targets(
        self, targets: list[MinerTarget]
    ) -> tuple[list[tuple[MinerTarget, str]], dict[str, MinerOutcome], frozenset[str]]:
        prepared: list[tuple[MinerTarget, str]] = []
        outcomes: dict[str, MinerOutcome] = {}
        groups: dict[str, list[MinerTarget]] = {}
        for target in targets:
            try:
                checked, endpoint = self._validate_target(target)
            except (TypeError, ValueError, RuntimeError) as exc:
                outcomes[target.hotkey] = MinerOutcome(
                    target.hotkey, target.endpoint_url, "invalid_endpoint", error=str(exc)
                )
                continue
            prepared.append((checked, endpoint))
            groups.setdefault(endpoint, []).append(checked)

        duplicate_hotkeys = {
            target.hotkey for group in groups.values() if len(group) > 1 for target in group
        }
        unique: list[tuple[MinerTarget, str]] = []
        for target, endpoint in prepared:
            if target.hotkey in duplicate_hotkeys:
                outcomes[target.hotkey] = MinerOutcome(
                    target.hotkey,
                    endpoint,
                    "duplicate_endpoint",
                    error="all claimants of a duplicate endpoint are excluded",
                )
            else:
                unique.append((target, endpoint))
        return unique, outcomes, frozenset(groups)

    def _attest_targets(
        self,
        prepared: list[tuple[MinerTarget, str]],
        outcomes: dict[str, MinerOutcome],
    ) -> list[_AttestationResult]:
        results: list[_AttestationResult] = []
        with ThreadPoolExecutor(max_workers=self._attestation_workers) as executor:
            futures: dict[str, Future[_AttestationResult]] = {
                target.hotkey: executor.submit(
                    self._collect_attestation_singleflight, target, endpoint
                )
                for target, endpoint in prepared
            }
            by_hotkey = {target.hotkey: (target, endpoint) for target, endpoint in prepared}
            for hotkey in sorted(futures):
                result = futures[hotkey].result()
                if result.attested is None:
                    target, endpoint = by_hotkey[hotkey]
                    if (
                        result.lifecycle_generation is not None
                        and result.lifecycle_revision is not None
                    ):
                        current = self.registry.lifecycle_snapshot(hotkey)
                        attempt = min(
                            current.retry_count + 1,
                            self.config.reattestation_failures_before_failed,
                        )
                        try:
                            self.registry.record_refresh_failure(
                                hotkey,
                                attempt=attempt,
                                maximum_attempts=self.config.reattestation_failures_before_failed,
                                retry_base_seconds=self.config.reattestation_retry_base_seconds,
                                retry_maximum_seconds=self.config.reattestation_retry_maximum_seconds,
                                retry_jitter_seconds=self.config.reattestation_retry_jitter_seconds,
                                operator_detail=result.error,
                                expected_generation=result.lifecycle_generation,
                                expected_revision=result.lifecycle_revision,
                            )
                        except LifecycleError:
                            # Another refresh, reenrollment, or terminal transition
                            # won the compare-and-swap. Ignore this stale result.
                            pass
                    outcomes[hotkey] = MinerOutcome(
                        hotkey,
                        endpoint,
                        "attestation_failed",
                        error=result.error,
                        error_category=result.error_category,
                    )
                else:
                    results.append(result)
        return results

    def _collect_attestation_singleflight(
        self, target: MinerTarget, endpoint: str
    ) -> _AttestationResult:
        snapshot = self.registry.lifecycle_snapshot(target.hotkey)
        if snapshot.state not in NETWORK_ELIGIBLE_STATES:
            return _AttestationResult(
                target,
                endpoint,
                error=f"worker lifecycle is {snapshot.state.value}",
                lifecycle_generation=snapshot.generation,
                lifecycle_revision=snapshot.revision,
            )
        try:
            result = self.reattestor.run(
                target.hotkey,
                snapshot.generation,
                lambda cancelled: self._collect_attestation(
                    target, endpoint, cancel_event=cancelled
                ),
                timeout_seconds=(
                    self.config.miner_timeout_seconds * self.config.miner_attempts * 2 + 1
                ),
            )
        except LifecycleError as exc:
            return _AttestationResult(
                target,
                endpoint,
                error=_safe_error(exc),
                lifecycle_generation=snapshot.generation,
                lifecycle_revision=snapshot.revision,
            )
        return replace(
            result,
            lifecycle_generation=snapshot.generation,
            lifecycle_revision=snapshot.revision,
        )

    def _admit_unique_chips(
        self,
        epoch_id: int,
        results: list[_AttestationResult],
        outcomes: dict[str, MinerOutcome],
    ) -> list[_AttestationResult]:
        chip_groups: dict[str, list[_AttestationResult]] = {}
        for result in results:
            assert result.attested is not None
            chip_groups.setdefault(result.attested.chip_id, []).append(result)

        admitted: list[_AttestationResult] = []
        for chip_id in sorted(chip_groups):
            group = chip_groups[chip_id]
            if len(group) > 1:
                for result in group:
                    self._revoke_lifecycle(result, LifecycleReason.IDENTITY_CONFLICT)
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "duplicate_chip",
                        error="all claimants of a duplicate chip are excluded",
                    )
                continue
            result = group[0]
            assert result.attested is not None and result.evidence_digest is not None
            current = self.registry.lifecycle_snapshot(
                result.target.hotkey, materialize_freshness=False
            )
            if (
                result.lifecycle_generation is None
                or result.lifecycle_revision is None
                or current.generation != result.lifecycle_generation
                or current.revision != result.lifecycle_revision
                or current.state not in NETWORK_ELIGIBLE_STATES
            ):
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "refresh_cancelled",
                    error="worker lifecycle changed during re-attestation",
                )
                continue
            rotation_owner = self.registry.chip_rotation_owner(chip_id, result.target.hotkey)
            if rotation_owner is not None:
                self._revoke_lifecycle(result, LifecycleReason.IDENTITY_CONFLICT)
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "chip_rotation_conflict",
                    error=f"chip_id already bound to hotkey {rotation_owner}",
                )
                continue
            pending_gpu_claim = None
            if result.attested.tier is Tier.CC_GPU:
                from cathedral.gpu import (
                    GpuAttestationError,
                    GpuComponentVerdict,
                    GpuIdentityRegistry,
                )

                if not isinstance(
                    self.gpu_identity_registry, GpuIdentityRegistry
                ) or not isinstance(result.gpu_component, GpuComponentVerdict):
                    raise RuntimeError("verified GPU admission is missing its identity component")
                self._require_live_gpu_profile()
                try:
                    pending_gpu_claim = self.gpu_identity_registry.begin_claim(
                        result.target.hotkey,
                        result.gpu_component,
                    )
                except GpuAttestationError as exc:
                    if exc.category != "identity_conflict":
                        raise
                    self._revoke_lifecycle(result, LifecycleReason.IDENTITY_CONFLICT)
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "gpu_identity_conflict",
                        error=_safe_error(exc),
                        error_category=exc.category,
                        component_audit=result.component_audit,
                    )
                    continue
            try:
                gpu_commit_authority = {}
                if result.attested.tier is Tier.CC_GPU and self.config.production_mode:
                    gpu_commit_authority = {
                        "gpu_profile_valid_from": self.gpu_profile.registry_valid_from,
                        "gpu_profile_valid_until": self.gpu_profile.registry_valid_until,
                        "gpu_profile_registry_release": self.gpu_profile.registry_release,
                        "gpu_profile_registry_digest": self.gpu_profile.registry_digest,
                    }
                self.registry.record_verdict(
                    result.target.hotkey,
                    result.attested,
                    expected_generation=result.lifecycle_generation,
                    expected_revision=result.lifecycle_revision,
                    policy_registry_release=self.policy.registry_release,
                    policy_registry_digest=self.policy.registry_digest,
                    **gpu_commit_authority,
                )
            except LifecycleError:
                if pending_gpu_claim is not None:
                    self.gpu_identity_registry.rollback_claim(pending_gpu_claim)
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "refresh_cancelled",
                    error="worker lifecycle changed during re-attestation",
                )
                continue
            except BaseException:
                if pending_gpu_claim is not None:
                    self.gpu_identity_registry.rollback_claim(pending_gpu_claim)
                raise
            if pending_gpu_claim is not None:
                # The lifecycle compare-and-swap is now accepted. Finalize the
                # durable GPU claim only at this last admission boundary.
                self.gpu_identity_registry.commit_claim(pending_gpu_claim)
            score_eligible = True
            if result.attested.tier is Tier.CC_GPU:
                from cathedral.gpu import gpu_score_eligible

                score_eligible = gpu_score_eligible(
                    result.attested,
                    profile=self.gpu_profile,
                    policy=self.policy,
                )
            self.ledger.add_attestation(
                epoch_id,
                result.target.hotkey,
                verdict="VERIFIED",
                tee_type=("TDX+GPU_CC" if result.attested.tier is Tier.CC_GPU else "TDX"),
                workload=("GPU" if result.attested.tier is Tier.CC_GPU else "CPU"),
                evidence_digest=result.evidence_digest,
                policy_mode=result.attested.policy_mode or "compatibility",
                score_eligible=score_eligible,
            )
            outcomes[result.target.hotkey] = MinerOutcome(
                result.target.hotkey,
                result.endpoint,
                "attested",
                admitted=True,
                assurance=result.attested.assurance,
                component_audit=result.component_audit,
            )
            admitted.append(result)
        return sorted(admitted, key=lambda result: result.target.hotkey)

    def _revoke_lifecycle(
        self,
        result: _AttestationResult,
        reason: LifecycleReason,
    ) -> None:
        current = self.registry.lifecycle_snapshot(
            result.target.hotkey, materialize_freshness=False
        )
        if current.state is WorkerLifecycleState.REVOKED:
            return
        self.registry.transition_lifecycle(
            result.target.hotkey,
            WorkerLifecycleState.REVOKED,
            reason,
            expected_generation=(
                result.lifecycle_generation
                if result.lifecycle_generation is not None
                else current.generation
            ),
            expected_revision=(
                result.lifecycle_revision
                if result.lifecycle_revision is not None
                else current.revision
            ),
        )
        self.reattestor.cancel(result.target.hotkey)

    def _run_sat(
        self,
        epoch_id: int,
        source_epoch: int,
        admitted: list[_AttestationResult],
        outcomes: dict[str, MinerOutcome],
    ) -> None:
        self._require_live_gpu_profile()
        lane = SatLane(
            namespace=f"source-epoch:{source_epoch}:attempt:{epoch_id}",
            gpu_profile=self.gpu_profile,
            gpu_policy=self.policy,
        )
        issued: list[tuple[_AttestationResult, SatWorkItem]] = []
        for result in admitted:
            assert result.attested is not None
            if not lane.qualify(result.attested):
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "tier_not_score_eligible",
                    admitted=True,
                    error="hardware tier is not enabled for SAT scoring",
                    assurance=result.attested.assurance,
                )
                continue
            if not WORK_DISPATCH_POLICY.allows(result.attested.assurance):
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "channel_binding_failed",
                    admitted=False,
                    error="protected work dispatch claims were not satisfied",
                    assurance=result.attested.assurance,
                )
                continue
            item = lane.dispatch(result.target.hotkey, budget=1)
            if not isinstance(item, SatWorkItem):
                raise RuntimeError("SAT lane returned a non-canonical work item")
            self.ledger.issue_challenge(item.challenge_id, result.target.hotkey, epoch_id)
            issued.append((result, item))

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(self._request_sat, result.client, item) for result, item in issued
            ]
            for (result, item), future in zip(issued, futures, strict=True):
                certificate, error = future.result()
                accepted = lane.verify(item, certificate) if certificate is not None else None
                if accepted is None:
                    assurance = _work_assurance(result.attested, item, certificate, passed=False)
                    self._resolve_work(
                        epoch_id,
                        source_epoch,
                        result,
                        item,
                        assurance,
                        status="failed",
                        work_units=0.0,
                    )
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "sat_failed",
                        admitted=True,
                        challenge_id=item.challenge_id,
                        error=error or "invalid SAT certificate",
                        assurance=assurance,
                    )
                    continue
                assurance = _work_assurance(result.attested, item, certificate, passed=True)
                if not SCORE_ELIGIBILITY_POLICY.allows(assurance):
                    self._resolve_work(
                        epoch_id,
                        source_epoch,
                        result,
                        item,
                        assurance,
                        status="failed",
                        work_units=0.0,
                    )
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "assurance_failed",
                        admitted=True,
                        challenge_id=item.challenge_id,
                        error="score eligibility claims were not satisfied",
                        assurance=assurance,
                    )
                    continue
                self._require_live_gpu_profile()
                units = lane.score(result.target.hotkey, [accepted])
                self._resolve_work(
                    epoch_id,
                    source_epoch,
                    result,
                    item,
                    assurance,
                    status="verified",
                    work_units=units,
                )
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "verified",
                    admitted=True,
                    challenge_id=item.challenge_id,
                    work_units=units,
                    assurance=assurance,
                )

    def _resolve_work(
        self,
        epoch_id: int,
        source_epoch: int,
        result: _AttestationResult,
        item: SatWorkItem,
        assurance: AssuranceClaims,
        *,
        status: str,
        work_units: float,
    ) -> None:
        if self.receipt_issuer is None:
            self.ledger.resolve_challenge(
                item.challenge_id,
                status,
                work_units,
                validator_derived=status == "verified",
            )
            return
        attested = result.attested
        assert attested is not None
        worker_lifecycle = self.registry.lifecycle_snapshot(result.target.hotkey)
        receipt = self.receipt_issuer.issue(
            epoch_id=epoch_id,
            source_epoch=source_epoch,
            subject_hotkey=result.target.hotkey,
            attested=attested,
            policy=self.policy,
            assurance=assurance,
            worker_lifecycle=worker_lifecycle,
            challenge_id=item.challenge_id,
            manifest_digest=_sat_manifest_digest(item),
            work_units=work_units,
        )
        issued_at = receipt.document["issued_at"]
        assert isinstance(issued_at, str)
        self.ledger.resolve_challenge_with_receipt(
            item.challenge_id,
            status,
            work_units,
            validator_derived=status == "verified",
            receipt_id=receipt.receipt_id,
            receipt_body=receipt.receipt_bytes,
            receipt_digest=receipt.receipt_digest,
            issued_at=issued_at,
        )

    def _collect_attestation(
        self,
        target: MinerTarget,
        endpoint: str,
        *,
        cancel_event: threading.Event | None = None,
    ) -> _AttestationResult:
        if cancel_event is not None and cancel_event.is_set():
            return _AttestationResult(target, endpoint, error="reattestation cancelled")
        try:
            remote_options = {
                "bearer_token": target.bearer_token,
                "timeout": self.config.miner_timeout_seconds,
                "allow_insecure_http": self.config.allow_insecure_http_for_tests,
            }
            if self.config.expected_tier is Tier.CC_GPU:
                remote_options["max_response_body"] = MAX_EVIDENCE_RESPONSE_BODY
            client = self.remote_factory(
                endpoint,
                target.hotkey,
                **remote_options,
            )
        except Exception as exc:
            return _AttestationResult(target, endpoint, error=_safe_error(exc))

        last_error = "attestation rejected"
        last_error_category = "attestation_rejected"
        for _ in range(self.config.miner_attempts):
            if cancel_event is not None and cancel_event.is_set():
                return _AttestationResult(target, endpoint, error="reattestation cancelled")
            gpu_budget_reserved = False
            try:
                nonce = self.nonce_factory()
                if not isinstance(nonce, bytes) or len(nonce) != 32:
                    raise RuntimeError("nonce_factory must return exactly 32 bytes")
                if self.config.expected_tier is Tier.CC_GPU:
                    # The response body, decoded evidence, and expanded verifier
                    # request coexist until composite verification finishes. Keep
                    # the validator-wide memory reservation for that full lifetime,
                    # including direct audit calls that bypass the worker pool.
                    self._gpu_evidence_slots.acquire()
                    gpu_budget_reserved = True
                    evidences = client.collect_evidence_bundle(nonce)
                    if (
                        not isinstance(evidences, tuple)
                        or len(evidences) != 2
                        or {evidence.kind for evidence in evidences}
                        != {EvidenceKind.TDX, EvidenceKind.GPU_CC}
                    ):
                        raise RuntimeError(
                            "GPU runtime requires exact TDX and GPU evidence components"
                        )
                else:
                    evidences = (client.collect_evidence(nonce),)
                if cancel_event is not None and cancel_event.is_set():
                    return _AttestationResult(target, endpoint, error="reattestation cancelled")
                if any(evidence.nonce != nonce for evidence in evidences):
                    raise RuntimeError("evidence nonce mismatch")
                if any(evidence.miner_hotkey != target.hotkey for evidence in evidences):
                    raise RuntimeError("evidence hotkey mismatch")
                tdx_evidence = next(
                    (evidence for evidence in evidences if evidence.kind is EvidenceKind.TDX),
                    None,
                )
                if tdx_evidence is None:
                    raise RuntimeError("TDX evidence component is required")
                if self.config.expected_tier is Tier.CC_GPU:
                    from cathedral.gpu import verify_composite_gpu

                    self._require_live_gpu_profile()
                    gpu_evidence = next(
                        evidence for evidence in evidences if evidence.kind is EvidenceKind.GPU_CC
                    )
                    composite = verify_composite_gpu(
                        tdx_evidence,
                        gpu_evidence,
                        nonce,
                        self.policy,
                        self.gpu_profile,
                        self.gpu_verifier,
                    )
                    self._require_live_gpu_profile()
                    verdict = composite.attested
                    evidence_digest = _evidence_bundle_digest(evidences)
                    component_audit = MappingProxyType(
                        {
                            "bundle_evidence_digest": evidence_digest,
                            "cpu": composite.cpu_audit,
                            "gpu": composite.gpu_audit,
                            "schema": "cathedral_composite_gpu_audit_v1",
                            "status": "verified",
                        }
                    )
                    gpu_component = composite.gpu_component
                else:
                    if len(evidences) != 1:
                        raise RuntimeError("CPU runtime requires one TDX component")
                    verdict = self.verifier(tdx_evidence, nonce, self.policy)
                    if verdict is None:
                        raise RuntimeError("TDX verification rejected")
                    evidence_digest = _evidence_digest(tdx_evidence)
                    component_audit = None
                    gpu_component = None
                if (
                    verdict.verification_status != "VERIFIED"
                    or verdict.tier is not self.config.expected_tier
                ):
                    raise RuntimeError("verdict does not match the requested hardware tier")
                if not verdict.chip_id:
                    raise RuntimeError("verified evidence must identify the hardware")
                if not ATTESTATION_ADMISSION_POLICY.allows(verdict.assurance):
                    raise RuntimeError(
                        "verdict does not satisfy hardware and software admission claims"
                    )
                if tdx_evidence.report_data_version == 2:
                    binding = client.confirm_channel_binding(tdx_evidence)
                    if cancel_event is not None and cancel_event.is_set():
                        return _AttestationResult(target, endpoint, error="reattestation cancelled")
                    if binding != tdx_evidence.channel_binding or any(
                        evidence.channel_binding != binding for evidence in evidences
                    ):
                        raise RuntimeError("live endpoint key does not match attested binding")
                    assert verdict.assurance is not None
                    verdict = replace(
                        verdict,
                        assurance=with_verified_channel(
                            verdict.assurance, binding.canonical_bytes()
                        ),
                    )
                elif self.config.production_mode:
                    raise RuntimeError("production evidence requires report data v2")
                if self.config.production_mode and not WORK_DISPATCH_POLICY.allows(
                    verdict.assurance
                ):
                    raise RuntimeError("production evidence requires a verified channel binding")
                return _AttestationResult(
                    target,
                    endpoint,
                    attested=verdict,
                    evidence_digest=evidence_digest,
                    client=client,
                    component_audit=component_audit,
                    gpu_component=gpu_component,
                )
            except Exception as exc:
                last_error = _safe_error(exc)
                last_error_category = _safe_error_category(exc)
            finally:
                if gpu_budget_reserved:
                    # Drop every local raw-evidence reference before another
                    # caller can reserve the validator-wide memory budget.
                    evidences = ()
                    tdx_evidence = None
                    gpu_evidence = None
                    self._gpu_evidence_slots.release()
        return _AttestationResult(
            target,
            endpoint,
            error=last_error,
            error_category=last_error_category,
        )

    def _request_sat(
        self, client: MinerClient | None, item: SatWorkItem
    ) -> tuple[SatCertificate | None, str | None]:
        if client is None:
            return None, "miner client unavailable"
        last_error = "SAT request failed"
        for _ in range(self.config.miner_attempts):
            try:
                return client.do_sat_work(item), None
            except Exception as exc:
                last_error = _safe_error(exc)
        return None, last_error

    def _validate_target(self, target: MinerTarget) -> tuple[MinerTarget, str]:
        if not isinstance(target, MinerTarget):
            raise TypeError("target must be a MinerTarget")
        if not isinstance(target.hotkey, str) or not target.hotkey:
            raise ValueError("target hotkey must be a nonempty string")
        _validate_bearer_token(
            target.bearer_token,
            required=self.config.production_mode,
        )
        endpoint = _canonical_endpoint(target.endpoint_url, self.config)
        return target, endpoint

    def _validate_required_auth(self, targets: tuple[MinerTarget, ...]) -> None:
        if not self.config.production_mode:
            return
        for target in targets:
            try:
                _validate_bearer_token(target.bearer_token, required=True)
            except ValueError as exc:
                raise RuntimeError(
                    f"production bearer authentication is required for target {target.hotkey!r}"
                ) from exc


def _work_assurance(
    attested: Attested,
    item: SatWorkItem,
    certificate: SatCertificate | None,
    *,
    passed: bool,
) -> AssuranceClaims:
    claims = attested.assurance
    if claims is None or claims.software.policy_digest is None:
        raise RuntimeError("attested verdict is missing typed assurance claims")
    material = {
        "assigned_hotkey": certificate.assigned_hotkey if certificate else None,
        "assignment": (
            list(certificate.assignment)
            if certificate is not None and isinstance(certificate.assignment, list)
            else None
        ),
        "challenge_id": item.challenge_id,
        "satisfiable": certificate.satisfiable if certificate else None,
        "work_units": certificate.work_units if certificate else None,
    }
    try:
        encoded = json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        encoded = json.dumps(
            {"challenge_id": item.challenge_id, "invalid_certificate": True},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    work = evaluated_claim(
        ClaimStatus.PASSED if passed else ClaimStatus.FAILED,
        encoded,
        SAT_WORK_POLICY_DIGEST,
        reason=None if passed else ReasonCategory.WORK_INVALID,
    )
    return claims.with_claim(AssuranceDimension.WORK, work)


def _sat_manifest_digest(item: SatWorkItem) -> str:
    manifest = {
        "schema": "cathedral_sat_manifest_v1",
        "challenge_id": item.challenge_id,
        "seed": item.seed,
        "instance": {
            "n_vars": item.instance.n_vars,
            "clauses": item.instance.clauses,
        },
    }
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return sha256_digest(encoded)


def _canonical_endpoint(endpoint: str, config: RuntimeConfig) -> str:
    if not isinstance(endpoint, str):
        raise ValueError("endpoint must be a string")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("endpoint must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint must not contain query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("endpoint must not contain a path")
    if parsed.scheme != "https" and not config.allow_insecure_http_for_tests:
        raise ValueError("endpoint must use HTTPS")

    host = parsed.hostname.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if config.production_mode:
            raise ValueError("production endpoint must use a public IP literal") from None
    else:
        if config.production_mode and not is_globally_routable(ip):
            raise ValueError("production endpoint must use a public address")
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint port is invalid") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    authority = host if port in {None, default_port} else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}"


def _validate_bearer_token(token: str | None, *, required: bool) -> None:
    if token is None and not required:
        return
    if (
        not isinstance(token, str)
        or not token
        or len(token) > MAX_BEARER_TOKEN_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
    ):
        raise ValueError("bearer token must be a nonempty bounded ASCII value")


def _evidence_digest(evidence: Evidence) -> str:
    digest = hashlib.sha256()
    binding = (
        evidence.channel_binding.canonical_bytes() if evidence.channel_binding is not None else b""
    )
    for value in (
        evidence.kind.value.encode("ascii"),
        evidence.quote,
        evidence.nonce,
        evidence.miner_hotkey.encode("utf-8"),
        evidence.report_data_version.to_bytes(2, "big"),
        binding,
        evidence.ssh_host_key or b"",
        evidence.composite_jwt.encode("utf-8") if evidence.composite_jwt else b"",
        *evidence.cert_chain,
    ):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _evidence_bundle_digest(evidences: tuple[Evidence, ...]) -> str:
    digest = hashlib.sha256(b"cathedral-evidence-bundle-v1\0")
    for evidence in sorted(evidences, key=lambda item: item.kind.value):
        component = bytes.fromhex(_evidence_digest(evidence))
        digest.update(evidence.kind.value.encode("ascii"))
        digest.update(component)
    return digest.hexdigest()


def _safe_error(exc: BaseException) -> str:
    message = str(exc).strip()
    return message[:300] if message else type(exc).__name__


def _safe_error_category(exc: BaseException) -> str:
    category = getattr(exc, "category", None)
    if (
        isinstance(category, str)
        and 1 <= len(category) <= 64
        and all(character.isalnum() or character == "_" for character in category)
    ):
        return category
    return "attestation_error"
