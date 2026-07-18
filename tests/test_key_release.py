"""Attestation-gated grant, broker, crash, replay, and privacy tests."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cathedral.assurance import attestation_claims, policy_digest, with_verified_channel
from cathedral.channel import application_key_binding
from cathedral.common import Attested, ChannelBinding, ChannelBindingType, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.key_release import (
    BrokerCustodyBoundary,
    BrokerPreflight,
    BrokerRedemptionRequest,
    EncryptedDataKeyEnvelope,
    GrantState,
    KeyReleaseError,
    KeyReleasePolicy,
    KeyReleaseService,
    KeyReleaseStore,
    LocalKeyBroker,
    WorkloadAssignmentAuthority,
)
from cathedral.lifecycle import LifecycleReason, WorkerLifecycleState, canonical_utc
from cathedral.workload import (
    ExternalSignatureVerifier,
    ExternalVerifierConfig,
    ImageReference,
    LocalSignatureVerifier,
    RecordingExecutionAdapter,
    SignatureVerdict,
    WorkloadAdmissionController,
    WorkloadAdmissionError,
    WorkloadAdmissionPolicy,
    WorkloadRequest,
)


START = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
REGISTRY_DIGEST = "sha256:" + "1" * 64
IMAGE_DIGEST = "sha256:" + "2" * 64
SIGNATURE_DIGEST = "sha256:" + "3" * 64
ARGUMENTS_DIGEST = "sha256:" + "4" * 64
CONFIG_DIGEST = "sha256:" + "5" * 64
IMAGE = f"registry.example.com/customer/job@{IMAGE_DIGEST}"
SIGNER = "sigstore://cathedral/customer-workload"
ROOT = "customer-root-v1"
HOTKEY = "worker-hotkey"
DATA_KEY_REFERENCE = "kms/customer/project/data-key-7"
PLAINTEXT_DATA_KEY = b"customer-data-key-material-32byte"
BROKER_CONFIG_DIGEST = "sha256:" + "6" * 64


@dataclass
class MutableClock:
    now: datetime = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class Harness:
    clock: MutableClock
    registry: RegistryStore
    attestation_policy: Policy
    workload_policy: WorkloadAdmissionPolicy
    workload_controller: WorkloadAdmissionController
    authority: WorkloadAssignmentAuthority
    assignment: object
    attested: Attested
    application_private_key: X25519PrivateKey
    application_public_key: bytes
    broker: LocalKeyBroker
    store: KeyReleaseStore
    service: KeyReleaseService
    active: dict[str, object]


def _attestation_policy(measurement: str = "measurement") -> Policy:
    return Policy(
        allowed_measurements={measurement},
        registry_release=7,
        registry_digest=REGISTRY_DIGEST,
        registry_profile_ids=("cpu-tdx-customer-v1",),
    )


def _workload_policy(**overrides) -> WorkloadAdmissionPolicy:
    values = {
        "policy_id": "customer-workload-v1",
        "allowed_registries": frozenset({"registry.example.com"}),
        "allowed_signers": frozenset({SIGNER}),
        "trusted_root_ids": frozenset({ROOT}),
        "allowed_resource_profiles": frozenset({"cpu-small"}),
        "allowed_runtime_profiles": frozenset({"confidential-cpu-v1"}),
    }
    values.update(overrides)
    return WorkloadAdmissionPolicy(**values)


def _workload_request() -> WorkloadRequest:
    return WorkloadRequest(
        image_reference=IMAGE,
        required_signer=SIGNER,
        arguments_digest=ARGUMENTS_DIGEST,
        config_digest=CONFIG_DIGEST,
        resource_profile="cpu-small",
        runtime_profile="confidential-cpu-v1",
    )


def _public_bytes(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _harness(tmp_path: Path, *, enabled: bool = True) -> Harness:
    clock = MutableClock()
    registry = RegistryStore(
        str(tmp_path / "registry.sqlite"),
        verification_ttl_seconds=300,
        clock=clock,
    )
    registry.enroll(HOTKEY, "https://worker.example")
    attestation_policy = _attestation_policy()
    application_private_key = X25519PrivateKey.generate()
    application_public_key = _public_bytes(application_private_key)
    binding = application_key_binding(application_public_key)
    claims = with_verified_channel(
        attestation_claims(
            b"quote-evidence",
            attestation_policy,
            verified_at=canonical_utc(clock.now),
        ),
        binding.canonical_bytes(),
        verified_at=canonical_utc(clock.now),
    )
    attested = Attested(
        Tier.CC_CPU_TDX,
        "chip-1",
        "measurement",
        1,
        assurance=claims,
    )
    registry.record_verdict(
        HOTKEY,
        attested,
        policy_registry_release=7,
        policy_registry_digest=REGISTRY_DIGEST,
    )

    workload_policy = _workload_policy()
    verifier = LocalSignatureVerifier(
        {
            IMAGE: SignatureVerdict(
                image_reference=IMAGE,
                signer_identity=SIGNER,
                trust_root_id=ROOT,
                signature_digest=SIGNATURE_DIGEST,
            )
        }
    )
    workload_controller = WorkloadAdmissionController(
        workload_policy,
        verifier,
        production_mode=False,
        capability_key=b"w" * 32,
    )
    admitted = workload_controller.admit(_workload_request())
    authority = WorkloadAssignmentAuthority(
        workload_controller,
        b"a" * 32,
        clock=clock,
        execution_worker_hotkey=HOTKEY,
    )
    assignment = authority.issue(
        authenticated_issuer_id="customer-account-7",
        worker_hotkey=HOTKEY,
        workload=admitted,
        data_key_reference=DATA_KEY_REFERENCE,
    )
    broker = LocalKeyBroker(
        {DATA_KEY_REFERENCE: PLAINTEXT_DATA_KEY},
        identity_digest_key=b"a" * 32,
    )
    store = KeyReleaseStore(tmp_path / "key-release.sqlite")
    active: dict[str, object] = {
        "attestation": attestation_policy,
        "workload": workload_policy,
    }
    service = KeyReleaseService(
        store,
        registry,
        authority,
        broker,
        lambda: active["attestation"],  # type: ignore[return-value]
        lambda: active["workload"],  # type: ignore[return-value]
        sealed_workloads_enabled=enabled,
        production_mode=False,
        clock=clock,
    )
    return Harness(
        clock,
        registry,
        attestation_policy,
        workload_policy,
        workload_controller,
        authority,
        assignment,
        attested,
        application_private_key,
        application_public_key,
        broker,
        store,
        service,
        active,
    )


def _service_with_broker(harness: Harness, broker) -> KeyReleaseService:
    return KeyReleaseService(
        harness.store,
        harness.registry,
        harness.authority,
        broker,
        lambda: harness.active["attestation"],  # type: ignore[return-value]
        lambda: harness.active["workload"],  # type: ignore[return-value]
        sealed_workloads_enabled=True,
        production_mode=False,
        clock=harness.clock,
    )


class ProductionSignatureVerifier:
    production_capable = True

    def preflight(self, trusted_root_ids: frozenset[str]) -> None:
        if trusted_root_ids != frozenset({ROOT}):
            raise AssertionError("unexpected roots")

    def verify(self, image, *, required_signer, trusted_root_ids):
        return SignatureVerdict(
            image_reference=image.canonical,
            signer_identity=required_signer,
            trust_root_id=next(iter(trusted_root_ids)),
            signature_digest=SIGNATURE_DIGEST,
        )


def _production_authority() -> WorkloadAssignmentAuthority:
    controller = WorkloadAdmissionController(
        _workload_policy(),
        ProductionSignatureVerifier(),
        production_mode=True,
        capability_key=b"p" * 32,
    )
    return WorkloadAssignmentAuthority(controller, b"q" * 32, clock=lambda: START)


def _broker_request(harness: Harness, grant) -> BrokerRedemptionRequest:
    assignment = harness.assignment
    return BrokerRedemptionRequest(
        grant_id=grant.grant_id,
        key_reference=assignment.data_key_reference,
        key_reference_digest=grant.data_key_reference_digest,
        application_public_key=harness.application_public_key,
        channel_key_digest=grant.channel_key_digest,
        manifest_digest=grant.manifest_digest,
        evidence_digest=grant.evidence_digest,
        grant_digest=grant.binding_digest,
        purpose=grant.purpose,
    )


def _decrypt(
    private_key: X25519PrivateKey,
    request: BrokerRedemptionRequest,
    envelope: EncryptedDataKeyEnvelope,
) -> bytes:
    ephemeral = X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope.ephemeral_public_key_b64, validate=True)
    )
    shared = private_key.exchange(ephemeral)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(request.channel_key_digest.removeprefix("sha256:")),
        info=b"cathedral-key-release-v1\0" + request.grant_id.encode("ascii"),
    ).derive(shared)
    return AESGCM(wrapping_key).decrypt(
        base64.b64decode(envelope.nonce_b64, validate=True),
        base64.b64decode(envelope.ciphertext_b64, validate=True),
        request.aad,
    )


def test_valid_grant_releases_only_ciphertext_decryptable_by_attested_key(tmp_path: Path):
    harness = _harness(tmp_path)

    grant = harness.service.issue_grant(
        harness.assignment,
        harness.attested,
        harness.application_public_key,
    )
    envelope = harness.service.redeem(
        grant.grant_id,
        harness.assignment,
        harness.application_public_key,
    )

    request = _broker_request(harness, grant)
    assert _decrypt(harness.application_private_key, request, envelope) == PLAINTEXT_DATA_KEY
    assert harness.broker.unwrap_count == 1
    persisted = harness.store.get(grant.grant_id)
    assert persisted.state is GrantState.REDEEMED
    assert persisted.envelope == envelope
    assert [event["to_state"] for event in harness.store.history(grant.grant_id)] == [
        "issued",
        "redeeming",
        "redeemed",
    ]


def test_grant_contains_exact_assignment_policy_lifecycle_and_channel_bindings(tmp_path: Path):
    harness = _harness(tmp_path)
    lifecycle = harness.registry.lifecycle_snapshot(HOTKEY)

    grant = harness.service.issue_grant(
        harness.assignment,
        harness.attested,
        harness.application_public_key,
    )

    assert grant.assignment_id == harness.assignment.assignment_id
    assert grant.manifest_digest == harness.assignment.manifest_digest
    assert grant.workload_policy_digest == harness.workload_policy.digest
    assert grant.attestation_policy_release == 7
    assert grant.attestation_policy_digest == REGISTRY_DIGEST
    assert grant.verification_policy_digest == policy_digest(harness.attestation_policy)
    assert grant.key_release_policy_digest == KeyReleasePolicy().digest
    assert (grant.worker_generation, grant.worker_revision, grant.worker_event_id) == (
        lifecycle.generation,
        lifecycle.revision,
        lifecycle.event_id,
    )
    assert grant.channel_key_digest == "sha256:" + application_key_binding(
        harness.application_public_key
    ).digest.hex()
    assert grant.expires_at == START + timedelta(seconds=60)


def test_repeated_grant_issuance_is_single_use_per_assignment(tmp_path: Path):
    harness = _harness(tmp_path)

    first = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    second = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    assert second.grant_id == first.grant_id
    assert second.issued_at == first.issued_at
    assert len(harness.store.history(first.grant_id)) == 1


def test_same_assignment_cannot_reuse_a_longer_grant_for_changed_timing(tmp_path: Path):
    harness = _harness(tmp_path)
    harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    with pytest.raises(KeyReleaseError) as shorter:
        harness.service.issue_grant(
            harness.assignment,
            harness.attested,
            harness.application_public_key,
            ttl_seconds=1,
        )
    assert shorter.value.category == "grant_conflict"

    harness.clock.advance(1)
    with pytest.raises(KeyReleaseError) as later:
        harness.service.issue_grant(
            harness.assignment, harness.attested, harness.application_public_key
        )
    assert later.value.category == "grant_conflict"


def test_same_channel_replay_returns_exact_persisted_ciphertext_without_unwrap(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    first = harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    calls = harness.broker.call_count
    second = harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )

    assert second.canonical_bytes == first.canonical_bytes
    assert harness.broker.unwrap_count == 1
    assert harness.broker.call_count == calls


def test_different_channel_replay_is_rejected_before_broker(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    other_public = _public_bytes(X25519PrivateKey.generate())

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(grant.grant_id, harness.assignment, other_public)

    assert raised.value.category == "channel_denied"
    assert harness.broker.call_count == 0


def test_concurrent_same_channel_redemption_unwraps_once_and_returns_same_bytes(
    tmp_path: Path,
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                harness.service.redeem,
                grant.grant_id,
                harness.assignment,
                harness.application_public_key,
            )
            for _ in range(2)
        ]
    envelopes = [future.result() for future in futures]

    assert envelopes[0].canonical_bytes == envelopes[1].canonical_bytes
    assert harness.broker.unwrap_count == 1


def test_crash_before_broker_response_retries_same_redeeming_grant(tmp_path: Path):
    harness = _harness(tmp_path)

    class FailsOnceBroker:
        production_capable = False

        def __init__(self, delegate):
            self.delegate = delegate
            self.failed = False

        def preflight(self):
            return self.delegate.preflight()

        def redeem(self, request):
            if not self.failed:
                self.failed = True
                raise RuntimeError("provider-credential=must-not-leak")
            return self.delegate.redeem(request)

    flaky = FailsOnceBroker(harness.broker)
    harness.service = _service_with_broker(harness, flaky)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )
    assert raised.value.category == "broker_unavailable"
    assert "credential" not in str(raised.value)
    assert harness.store.get(grant.grant_id).state is GrantState.REDEEMING

    envelope = harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    assert envelope.grant_id == grant.grant_id
    assert harness.broker.unwrap_count == 1


def test_crash_after_broker_response_before_persistence_does_not_mint_second_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    original = harness.store.persist_redemption
    failed = False

    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise KeyReleaseError("store_unavailable", "simulated crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.store, "persist_redemption", fail_once)

    with pytest.raises(KeyReleaseError, match="simulated crash"):
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )
    assert harness.broker.unwrap_count == 1
    assert harness.store.get(grant.grant_id).state is GrantState.REDEEMING

    recovered = harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    assert harness.broker.unwrap_count == 1
    assert harness.broker.call_count == 2
    assert harness.store.get(grant.grant_id).envelope == recovered


@pytest.mark.parametrize(
    ("advance", "accepted"),
    [(59, True), (60, False)],
)
def test_attestation_age_boundary_is_exact(tmp_path: Path, advance: int, accepted: bool):
    harness = _harness(tmp_path)
    harness.clock.advance(advance)

    if accepted:
        grant = harness.service.issue_grant(
            harness.assignment, harness.attested, harness.application_public_key
        )
        assert grant.state is GrantState.ISSUED
    else:
        with pytest.raises(KeyReleaseError) as raised:
            harness.service.issue_grant(
                harness.assignment, harness.attested, harness.application_public_key
            )
        assert raised.value.category == "attestation_stale"


def test_grant_ttl_cannot_exceed_policy_or_evidence_window(tmp_path: Path):
    harness = _harness(tmp_path)
    with pytest.raises(KeyReleaseError, match="grant TTL"):
        harness.service.issue_grant(
            harness.assignment,
            harness.attested,
            harness.application_public_key,
            ttl_seconds=61,
        )

    harness.clock.advance(50)
    grant = harness.service.issue_grant(
        harness.assignment,
        harness.attested,
        harness.application_public_key,
        ttl_seconds=30,
    )
    assert grant.expires_at == START + timedelta(seconds=60)


def test_freshness_deadline_blocks_ciphertext_return_after_late_issuance(tmp_path: Path):
    harness = _harness(tmp_path)
    harness.clock.advance(59)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    assert grant.expires_at == START + timedelta(seconds=60)

    harness.clock.advance(1)
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "grant_expired"
    assert harness.broker.call_count == 0


def test_expired_grant_cannot_call_broker_or_reissue_ciphertext(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.clock.advance(60)

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "grant_expired"
    assert harness.broker.call_count == 0


def test_grant_expiry_is_capped_by_assignment_and_rechecked_after_broker(tmp_path: Path):
    harness = _harness(tmp_path)
    admitted = harness.workload_controller.admit(_workload_request())
    short_assignment = harness.authority.issue(
        authenticated_issuer_id="customer-account-7",
        worker_hotkey=HOTKEY,
        workload=admitted,
        data_key_reference=DATA_KEY_REFERENCE,
        ttl_seconds=1,
    )
    grant = harness.service.issue_grant(
        short_assignment, harness.attested, harness.application_public_key
    )
    assert grant.expires_at == short_assignment.expires_at
    delegate = harness.broker

    class CrossingBroker:
        def preflight(self):
            return delegate.preflight()

        def redeem(self, request):
            envelope = delegate.redeem(request)
            harness.clock.advance(1)
            return envelope

    harness.service = _service_with_broker(harness, CrossingBroker())
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, short_assignment, harness.application_public_key
        )

    assert raised.value.category == "grant_expired"
    assert harness.store.get(grant.grant_id).envelope is None


def test_redeemed_replay_rechecks_expiry_after_store_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    original = harness.store.begin_redemption

    def cross_expiry(*args, **kwargs):
        persisted = original(*args, **kwargs)
        harness.clock.advance(60)
        return persisted

    monkeypatch.setattr(harness.store, "begin_redemption", cross_expiry)
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "grant_expired"
    assert harness.broker.unwrap_count == 1


def test_redeemed_replay_rechecks_revocation_after_store_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    original = harness.store.begin_redemption

    def revoke_after_lookup(*args, **kwargs):
        persisted = original(*args, **kwargs)
        harness.registry.transition_lifecycle(
            HOTKEY,
            WorkerLifecycleState.REVOKED,
            LifecycleReason.POLICY_REVOKED,
        )
        return persisted

    monkeypatch.setattr(harness.store, "begin_redemption", revoke_after_lookup)
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "attestation_revoked"
    assert harness.broker.unwrap_count == 1


def test_final_release_resamples_time_after_slow_state_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    original = harness.service._validate_current
    validation_calls = 0

    def crosses_deadline(*args, **kwargs):
        nonlocal validation_calls
        validation_calls += 1
        original(*args, **kwargs)
        if validation_calls == 2:
            harness.clock.advance(60)

    monkeypatch.setattr(harness.service, "_validate_current", crosses_deadline)
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "grant_expired"
    assert harness.broker.unwrap_count == 1


def test_clock_rollback_fails_closed_before_ciphertext_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.clock.advance(1)
    original = harness.service._validate_current
    validation_calls = 0

    def rolls_back(*args, **kwargs):
        nonlocal validation_calls
        validation_calls += 1
        original(*args, **kwargs)
        if validation_calls == 2:
            harness.clock.now -= timedelta(seconds=1)

    monkeypatch.setattr(harness.service, "_validate_current", rolls_back)
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "clock_invalid"
    assert harness.store.get(grant.grant_id).envelope is not None


def test_concurrent_clock_samples_are_ordered_before_sampling(tmp_path: Path):
    harness = _harness(tmp_path)

    class OrderedClock:
        def __init__(self):
            self.calls = 0
            self.state_lock = threading.Lock()
            self.first_entered = threading.Event()
            self.release_first = threading.Event()
            self.second_entered = threading.Event()

        def __call__(self):
            with self.state_lock:
                self.calls += 1
                call = self.calls
            if call == 1:
                self.first_entered.set()
                assert self.release_first.wait(2)
                return START
            self.second_entered.set()
            return START + timedelta(seconds=1)

    clock = OrderedClock()
    service = KeyReleaseService(
        harness.store,
        harness.registry,
        harness.authority,
        harness.broker,
        lambda: harness.attestation_policy,
        lambda: harness.workload_policy,
        sealed_workloads_enabled=False,
        production_mode=False,
        clock=clock,
    )
    second_started = threading.Event()

    def second_sample():
        second_started.set()
        return service._now()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service._now)
        assert clock.first_entered.wait(1)
        second = executor.submit(second_sample)
        assert second_started.wait(1)
        assert not clock.second_entered.wait(0.1)
        clock.release_first.set()
        assert first.result() == START
        assert second.result() == START + timedelta(seconds=1)


def test_registry_samples_clock_at_state_consumption_not_from_stale_service_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    original = harness.registry.lifecycle_snapshot
    calls: list[dict[str, object]] = []

    def records_call(*args, **kwargs):
        calls.append(dict(kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.registry, "lifecycle_snapshot", records_call)
    harness.service._validate_current(grant, at=START)

    assert calls == [{}]


def test_registry_orders_clock_sampling_across_store_instances(tmp_path: Path):
    harness = _harness(tmp_path)
    peer = RegistryStore(harness.registry.path, clock=harness.clock)

    class OrderedRegistryClock:
        def __init__(self):
            self.calls = 0
            self.state_lock = threading.Lock()
            self.first_entered = threading.Event()
            self.release_first = threading.Event()
            self.second_entered = threading.Event()

        def __call__(self):
            with self.state_lock:
                self.calls += 1
                call = self.calls
            if call == 1:
                self.first_entered.set()
                assert self.release_first.wait(2)
                return START
            self.second_entered.set()
            return START + timedelta(seconds=1)

    clock = OrderedRegistryClock()
    harness.registry._clock = clock
    peer._clock = clock
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            harness.registry.lifecycle_snapshot,
            HOTKEY,
            materialize_freshness=False,
        )
        assert clock.first_entered.wait(1)
        second = executor.submit(
            peer.lifecycle_snapshot,
            HOTKEY,
            materialize_freshness=False,
        )
        assert not clock.second_entered.wait(0.1)
        clock.release_first.set()
        assert first.result().state is WorkerLifecycleState.ATTESTED
        assert second.result().state is WorkerLifecycleState.ATTESTED


def test_registry_initialization_orders_backfill_clock_across_instances(tmp_path: Path):
    harness = _harness(tmp_path)

    class OrderedInitializationClock:
        def __init__(self):
            self.calls = 0
            self.state_lock = threading.Lock()
            self.first_entered = threading.Event()
            self.release_first = threading.Event()
            self.second_entered = threading.Event()

        def __call__(self):
            with self.state_lock:
                self.calls += 1
                call = self.calls
            if call == 1:
                self.first_entered.set()
                assert self.release_first.wait(2)
                return START
            self.second_entered.set()
            return START + timedelta(seconds=1)

    clock = OrderedInitializationClock()

    def open_store():
        return RegistryStore(
            harness.registry.path,
            verification_ttl_seconds=300,
            clock=clock,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(open_store)
        assert clock.first_entered.wait(1)
        second = executor.submit(open_store)
        assert not clock.second_entered.wait(0.1)
        clock.release_first.set()
        assert isinstance(first.result(), RegistryStore)
        assert isinstance(second.result(), RegistryStore)


def test_policy_revocation_blocks_redemption_without_broker_call(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.active["attestation"] = _attestation_policy("different-measurement")

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "policy_revoked"
    assert harness.broker.call_count == 0


def test_verifier_policy_change_under_same_registry_release_revokes_grant(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.active["attestation"] = dataclasses.replace(
        harness.attestation_policy,
        min_tcb=2,
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "policy_revoked"
    assert harness.broker.call_count == 0


def test_workload_policy_change_blocks_redemption(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.active["workload"] = _workload_policy(
        allowed_resource_profiles=frozenset({"cpu-large"})
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "policy_revoked"
    assert harness.broker.call_count == 0


def test_lifecycle_revocation_blocks_redemption_and_prior_ciphertext_reissue(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )
    harness.clock.advance(1)
    harness.registry.transition_lifecycle(
        HOTKEY,
        WorkerLifecycleState.REVOKED,
        LifecycleReason.POLICY_REVOKED,
    )
    calls = harness.broker.call_count

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "attestation_revoked"
    assert harness.broker.call_count == calls


def test_lifecycle_revision_change_invalidates_unredeemed_grant(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    current = harness.registry.lifecycle_snapshot(HOTKEY)
    harness.clock.advance(1)
    harness.registry.record_refresh_failure(
        HOTKEY,
        attempt=1,
        maximum_attempts=3,
        expected_generation=current.generation,
        expected_revision=current.revision,
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "attestation_revoked"


def test_revocation_during_broker_call_is_rechecked_before_persistence(tmp_path: Path):
    harness = _harness(tmp_path)
    delegate = harness.broker

    class RevokingBroker:
        production_capable = False

        def preflight(self):
            return delegate.preflight()

        def redeem(self, request):
            envelope = delegate.redeem(request)
            harness.clock.advance(1)
            harness.registry.transition_lifecycle(
                HOTKEY,
                WorkerLifecycleState.REVOKED,
                LifecycleReason.POLICY_REVOKED,
            )
            return envelope

    harness.service = _service_with_broker(harness, RevokingBroker())
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "attestation_revoked"
    assert harness.store.get(grant.grant_id).state is GrantState.REDEEMING
    assert harness.store.get(grant.grant_id).envelope is None


def test_wrong_application_key_cannot_receive_grant(tmp_path: Path):
    harness = _harness(tmp_path)
    other_public = _public_bytes(X25519PrivateKey.generate())

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(
            harness.assignment, harness.attested, other_public
        )

    assert raised.value.category == "channel_denied"


def test_caller_cannot_forge_channel_claim_around_persisted_verifier_record(
    tmp_path: Path,
):
    harness = _harness(tmp_path)
    attacker_private_key = X25519PrivateKey.generate()
    attacker_public_key = _public_bytes(attacker_private_key)
    assert harness.attested.assurance is not None
    forged = dataclasses.replace(
        harness.attested,
        assurance=with_verified_channel(
            harness.attested.assurance,
            application_key_binding(attacker_public_key).canonical_bytes(),
            verified_at=canonical_utc(harness.clock.now),
        ),
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(
            harness.assignment,
            forged,
            attacker_public_key,
        )

    assert raised.value.category == "attestation_denied"
    with sqlite3.connect(harness.store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM key_release_grants").fetchone()[0] == 0


def test_low_order_x25519_key_is_rejected_before_broker(tmp_path: Path):
    harness = _harness(tmp_path)

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(harness.assignment, harness.attested, b"\x00" * 32)

    assert raised.value.category == "channel_denied"


def test_tls_binding_cannot_substitute_for_application_encryption_key(tmp_path: Path):
    harness = _harness(tmp_path)
    tls_binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
    claims = with_verified_channel(
        attestation_claims(
            b"quote-evidence",
            harness.attestation_policy,
            verified_at=canonical_utc(START),
        ),
        tls_binding.canonical_bytes(),
        verified_at=canonical_utc(START),
    )
    attested = dataclasses.replace(harness.attested, assurance=claims)
    harness.registry.record_verdict(
        HOTKEY,
        attested,
        policy_registry_release=7,
        policy_registry_digest=REGISTRY_DIGEST,
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(
            harness.assignment, attested, harness.application_public_key
        )

    assert raised.value.category == "channel_denied"


def test_forged_assignment_owner_worker_or_manifest_is_rejected(tmp_path: Path):
    harness = _harness(tmp_path)
    replacements = [
        {"issuer_id": "attacker"},
        {"worker_hotkey": "other-worker"},
        {"manifest_digest": "sha256:" + "0" * 64},
        {"data_key_reference": "kms/other/key"},
        {"production_admission": True},
    ]

    for replacement in replacements:
        forged = dataclasses.replace(harness.assignment, **replacement)
        with pytest.raises(KeyReleaseError) as raised:
            harness.service.issue_grant(
                forged, harness.attested, harness.application_public_key
            )
        assert raised.value.category == "invalid_assignment"


def test_authenticated_assignment_dispatches_exact_manifest_idempotently(tmp_path: Path):
    harness = _harness(tmp_path)
    admitted = harness.workload_controller.admit(_workload_request())
    adapter = RecordingExecutionAdapter()

    result = harness.authority.dispatch_execution(
        assignment=harness.assignment,
        workload=admitted,
        adapter=adapter,
    )

    assert result.execution_id == harness.assignment.assignment_id
    assert result.manifest_digest == harness.assignment.manifest_digest
    assert adapter.workloads == [(harness.assignment.assignment_id, admitted)]


@pytest.mark.parametrize("changed", ["worker", "manifest", "expired"])
def test_assignment_execution_binding_fails_before_provider(
    tmp_path: Path,
    changed: str,
):
    harness = _harness(tmp_path)
    admitted = harness.workload_controller.admit(_workload_request())
    if changed == "worker":
        assignment = harness.authority.issue(
            authenticated_issuer_id="customer-account-7",
            worker_hotkey="different-worker",
            workload=admitted,
            data_key_reference=DATA_KEY_REFERENCE,
        )
    elif changed == "manifest":
        assignment = harness.assignment
        admitted = harness.workload_controller.admit(
            dataclasses.replace(
                _workload_request(),
                config_digest="sha256:" + "9" * 64,
            )
        )
    else:
        assignment = harness.assignment
        harness.clock.now = harness.assignment.expires_at
    adapter = RecordingExecutionAdapter()

    with pytest.raises(KeyReleaseError) as raised:
        harness.authority.dispatch_execution(
            assignment=assignment,
            workload=admitted,
            adapter=adapter,
        )

    assert raised.value.category in {"execution_denied", "invalid_assignment"}
    assert adapter.workloads == []


def test_development_bypass_cannot_become_authenticated_assignment(tmp_path: Path):
    harness = _harness(tmp_path)
    bypassed = harness.workload_controller.development_bypass(
        _workload_request(), reason="test-only"
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.authority.issue(
            authenticated_issuer_id="customer-account-7",
            worker_hotkey=HOTKEY,
            workload=bypassed,
            data_key_reference=DATA_KEY_REFERENCE,
        )

    assert raised.value.category == "invalid_assignment"


def test_unapproved_purpose_is_rejected(tmp_path: Path):
    harness = _harness(tmp_path)
    admitted = harness.workload_controller.admit(_workload_request())
    assignment = harness.authority.issue(
        authenticated_issuer_id="customer-account-7",
        worker_hotkey=HOTKEY,
        workload=admitted,
        data_key_reference=DATA_KEY_REFERENCE,
        purpose="unapproved-purpose",
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(
            assignment, harness.attested, harness.application_public_key
        )

    assert raised.value.category == "purpose_denied"


def test_restarted_service_revokes_existing_grant_when_key_release_policy_changes(
    tmp_path: Path,
):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    restarted = KeyReleaseService(
        harness.store,
        harness.registry,
        harness.authority,
        harness.broker,
        lambda: harness.attestation_policy,
        lambda: harness.workload_policy,
        policy=KeyReleasePolicy(allowed_purposes=frozenset({"replacement-purpose"})),
        sealed_workloads_enabled=True,
        production_mode=False,
        clock=harness.clock,
    )

    with pytest.raises(KeyReleaseError) as raised:
        restarted.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "policy_revoked"
    assert harness.broker.call_count == 0


def test_expired_assignment_cannot_issue_or_redeem(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.clock.advance(300)

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "invalid_assignment"


def test_store_never_persists_plaintext_key_reference_public_key_or_issuer(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )

    database = Path(harness.store.path).read_bytes()
    assert PLAINTEXT_DATA_KEY not in database
    assert DATA_KEY_REFERENCE.encode() not in database
    assert harness.application_public_key not in database
    assert b"customer-account-7" not in database
    with sqlite3.connect(harness.store.path) as connection:
        issuer_digest, reference_digest = connection.execute(
            "SELECT issuer_digest,data_key_reference_digest FROM key_release_grants"
        ).fetchone()
    enumerable_issuer = "sha256:" + hashlib.sha256(
        b"cathedral-assignment-issuer-v1\0customer-account-7"
    ).hexdigest()
    enumerable_reference = "sha256:" + hashlib.sha256(
        b"cathedral-data-key-reference-v1\0" + DATA_KEY_REFERENCE.encode()
    ).hexdigest()
    assert issuer_digest != enumerable_issuer
    assert reference_digest != enumerable_reference


def test_public_grant_omits_internal_policy_channel_key_and_custody_details(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    public = dict(grant.public_dict())
    operator = dict(grant.operator_dict())

    assert public["schema"] == "cathedral_attestation_grant_v1"
    assert "channel_key_digest" not in public
    assert "data_key_reference_digest" not in public
    assert "evidence_digest" not in public
    assert "issuer_digest" not in public
    assert operator["channel_key_digest"] == grant.channel_key_digest
    assert DATA_KEY_REFERENCE not in str(operator)


def test_persisted_ciphertext_survives_restart_as_exact_bytes(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    envelope = harness.service.redeem(
        grant.grant_id, harness.assignment, harness.application_public_key
    )

    reopened = KeyReleaseStore(harness.store.path).get(grant.grant_id)

    assert reopened.envelope is not None
    assert reopened.envelope.canonical_bytes == envelope.canonical_bytes
    assert reopened.state is GrantState.REDEEMED


def test_append_only_audit_history_rejects_update_and_delete(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )
    with sqlite3.connect(harness.store.path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("UPDATE key_release_events SET reason='rewritten'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("DELETE FROM key_release_events")
    assert len(harness.store.history(grant.grant_id)) == 1


def test_broker_mismatched_envelope_is_rejected_without_persistence(tmp_path: Path):
    harness = _harness(tmp_path)
    delegate = harness.broker

    class MismatchedBroker:
        production_capable = False

        def preflight(self):
            return delegate.preflight()

        def redeem(self, request):
            envelope = delegate.redeem(request)
            return dataclasses.replace(envelope, request_digest="sha256:" + "0" * 64)

    harness.service = _service_with_broker(harness, MismatchedBroker())
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "broker_rejected"
    assert harness.store.get(grant.grant_id).envelope is None


def test_feature_gate_denies_all_release_when_disabled(tmp_path: Path):
    harness = _harness(tmp_path, enabled=False)

    with pytest.raises(AttributeError):
        harness.service.sealed_workloads_enabled = True  # type: ignore[misc]
    with pytest.raises(AttributeError):
        harness.service.broker = harness.broker  # type: ignore[misc]
    for name, value in (
        ("_LOCKED_SECURITY_CONFIGURATION", frozenset()),
        ("_sealed_workloads_enabled", True),
        ("_production_mode", True),
        ("_broker", harness.broker),
        ("_required_broker_configuration_digest", BROKER_CONFIG_DIGEST),
        ("_configuration_locked", False),
    ):
        with pytest.raises(AttributeError):
            setattr(harness.service, name, value)

    with pytest.raises(KeyReleaseError) as raised:
        harness.service.issue_grant(
            harness.assignment, harness.attested, harness.application_public_key
        )

    assert raised.value.category == "feature_disabled"


def test_production_refuses_local_broker_and_preflight_failure_is_secret_safe(
    tmp_path: Path,
):
    harness = _harness(tmp_path)
    production_authority = _production_authority()
    with pytest.raises(KeyReleaseError) as local:
        KeyReleaseService(
            harness.store,
            harness.registry,
            production_authority,
            harness.broker,
            lambda: harness.attestation_policy,
            lambda: harness.workload_policy,
            sealed_workloads_enabled=True,
            production_mode=True,
            required_broker_configuration_digest=BROKER_CONFIG_DIGEST,
            clock=harness.clock,
        )
    assert local.value.category == "broker_unavailable"

    class FailedProductionBroker:
        def preflight(self):
            raise RuntimeError("root-credential=do-not-leak")

        def redeem(self, _request):
            raise AssertionError

    with pytest.raises(KeyReleaseError) as preflight:
        KeyReleaseService(
            harness.store,
            harness.registry,
            production_authority,
            FailedProductionBroker(),
            lambda: harness.attestation_policy,
            lambda: harness.workload_policy,
            sealed_workloads_enabled=True,
            production_mode=True,
            required_broker_configuration_digest=BROKER_CONFIG_DIGEST,
            clock=harness.clock,
        )
    assert preflight.value.category == "broker_unavailable"
    assert "credential" not in str(preflight.value)


def test_production_rejects_development_workload_assignment_authority(tmp_path: Path):
    harness = _harness(tmp_path)
    unsafe = harness.workload_controller.admit(
        dataclasses.replace(_workload_request(), privileged=True, host_network=True)
    )
    unsafe_assignment = harness.authority.issue(
        authenticated_issuer_id="customer-account-7",
        worker_hotkey=HOTKEY,
        workload=unsafe,
        data_key_reference=DATA_KEY_REFERENCE,
    )
    assert unsafe_assignment.production_admission is False
    assert unsafe.production_admission is False

    with pytest.raises(AttributeError):
        harness.workload_controller.production_mode = True
    with pytest.raises(AttributeError):
        harness.workload_controller.verifier = ProductionSignatureVerifier()
    with pytest.raises(AttributeError):
        harness.workload_controller._preflight_complete = True
    with pytest.raises(AttributeError):
        harness.workload_controller._LOCKED_SECURITY_CONFIGURATION = frozenset()

    class ReadyBroker:
        def preflight(self):
            return BrokerPreflight(
                configuration_digest=BROKER_CONFIG_DIGEST,
                custody_boundary=BrokerCustodyBoundary.EXTERNAL_KMS,
                ciphertext_only=True,
                durable_idempotency=True,
                request_binding=True,
            )

        def redeem(self, _request):
            raise AssertionError

    with pytest.raises(KeyReleaseError) as raised:
        KeyReleaseService(
            harness.store,
            harness.registry,
            harness.authority,
            ReadyBroker(),
            lambda: harness.attestation_policy,
            lambda: harness.workload_policy,
            sealed_workloads_enabled=True,
            production_mode=True,
            required_broker_configuration_digest=BROKER_CONFIG_DIGEST,
            clock=harness.clock,
        )

    assert raised.value.category == "assignment_unavailable"
    production_authority = _production_authority()
    with pytest.raises(WorkloadAdmissionError) as dispatch:
        production_authority.workload_controller.validate_admission(unsafe)
    assert dispatch.value.category == "execution_denied"
    admitted = production_authority.workload_controller.admit(_workload_request())
    production_assignment = production_authority.issue(
        authenticated_issuer_id="customer-account-7",
        worker_hotkey=HOTKEY,
        workload=admitted,
        data_key_reference=DATA_KEY_REFERENCE,
    )
    assert production_assignment.production_admission is True


def test_production_broker_requires_pinned_structured_custody_preflight(tmp_path: Path):
    harness = _harness(tmp_path)
    production_authority = _production_authority()

    class StructuredBroker:
        def __init__(self, preflight):
            self.result = preflight

        def preflight(self):
            return self.result

        def redeem(self, _request):
            raise AssertionError

    ready = BrokerPreflight(
        configuration_digest=BROKER_CONFIG_DIGEST,
        custody_boundary=BrokerCustodyBoundary.EXTERNAL_KMS,
        ciphertext_only=True,
        durable_idempotency=True,
        request_binding=True,
    )
    service = KeyReleaseService(
        harness.store,
        harness.registry,
        production_authority,
        StructuredBroker(ready),
        lambda: harness.attestation_policy,
        lambda: harness.workload_policy,
        sealed_workloads_enabled=True,
        production_mode=True,
        required_broker_configuration_digest=BROKER_CONFIG_DIGEST,
        clock=harness.clock,
    )
    assert service.required_broker_configuration_digest == BROKER_CONFIG_DIGEST

    for rejected in (
        dataclasses.replace(ready, configuration_digest="sha256:" + "7" * 64),
        dataclasses.replace(ready, custody_boundary=BrokerCustodyBoundary.LOCAL_TEST),
        dataclasses.replace(ready, ciphertext_only=False),
        dataclasses.replace(ready, durable_idempotency=False),
        dataclasses.replace(ready, request_binding=False),
    ):
        with pytest.raises(KeyReleaseError) as raised:
            KeyReleaseService(
                harness.store,
                harness.registry,
                production_authority,
                StructuredBroker(rejected),
                lambda: harness.attestation_policy,
                lambda: harness.workload_policy,
                sealed_workloads_enabled=True,
                production_mode=True,
                required_broker_configuration_digest=BROKER_CONFIG_DIGEST,
                clock=harness.clock,
            )
        assert raised.value.category == "broker_unavailable"

    with pytest.raises(KeyReleaseError, match="not pinned"):
        KeyReleaseService(
            harness.store,
            harness.registry,
            production_authority,
            StructuredBroker(ready),
            lambda: harness.attestation_policy,
            lambda: harness.workload_policy,
            sealed_workloads_enabled=True,
            production_mode=True,
            clock=harness.clock,
        )


def test_policy_provider_exception_is_secret_safe_and_never_calls_broker(tmp_path: Path):
    harness = _harness(tmp_path)
    grant = harness.service.issue_grant(
        harness.assignment, harness.attested, harness.application_public_key
    )

    def fails():
        raise RuntimeError("policy-token=do-not-leak")

    harness.service.attestation_policy_provider = fails
    with pytest.raises(KeyReleaseError) as raised:
        harness.service.redeem(
            grant.grant_id, harness.assignment, harness.application_public_key
        )

    assert raised.value.category == "policy_unavailable"
    assert "token" not in str(raised.value)
    assert harness.broker.call_count == 0


def test_invalid_release_policy_types_fail_closed():
    with pytest.raises(KeyReleaseError):
        KeyReleasePolicy(max_grant_ttl_seconds=True)  # type: ignore[arg-type]
    with pytest.raises(KeyReleaseError):
        KeyReleasePolicy(clock_skew_seconds=6)
    with pytest.raises(KeyReleaseError):
        KeyReleasePolicy(allowed_purposes=frozenset())
    with pytest.raises(KeyReleaseError):
        KeyReleasePolicy(max_attestation_age_seconds=61)


def test_external_signature_verifier_is_not_accidentally_used_as_key_broker():
    assert not hasattr(ExternalSignatureVerifier, "redeem")
    assert ImageReference.parse(IMAGE).digest == IMAGE_DIGEST


def test_external_signature_verifier_configuration_is_immutable_after_preflight():
    original = ExternalVerifierConfig(("/usr/bin/true",))
    replacement = ExternalVerifierConfig(("/usr/bin/false",))
    verifier = ExternalSignatureVerifier(original)

    with pytest.raises(AttributeError):
        verifier.config = replacement  # type: ignore[misc]
    with pytest.raises(AttributeError):
        verifier._config = replacement
    assert verifier.config is original
