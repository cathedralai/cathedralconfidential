"""Focused integration tests for the confidential report runtime."""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

import pytest

import cathedral.runtime as runtime_module

from cathedral.assurance import ClaimStatus, attestation_claims
from cathedral.common import (
    Attested,
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    Policy,
    Tier,
    issue_nonce,
)
from cathedral.enroll import RegistryStore
from cathedral.lanes.sat import SatLane, solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.ledger import Ledger, LedgerError
from cathedral.receipt import ReceiptIssuer, verify_receipt
from cathedral.runtime import (
    ConfidentialRuntime,
    MinerTarget,
    RuntimeConfig,
    RuntimeError,
    SAT_WORK_POLICY_DIGEST,
    _evidence_digest,
    _work_assurance,
)


CANARY = MinerTarget("canary", "http://127.0.0.1:9000")


@dataclass
class MinerSpec:
    chip: str
    evidence_failures: int = 0
    sat_failures: int = 0
    invalid_sat: bool = False
    evidence_kind: EvidenceKind = EvidenceKind.TDX
    channel_mismatch: bool = False
    legacy_evidence: bool = False


class FakeClient:
    def __init__(self, endpoint: str, hotkey: str, spec: MinerSpec, log: dict[str, list]) -> None:
        self.endpoint = endpoint
        self.hotkey = hotkey
        self.spec = spec
        self.log = log
        self.evidence_calls = 0
        self.sat_calls = 0
        self.binding = ChannelBinding(
            ChannelBindingType.APPLICATION_KEY_SHA256,
            hashlib.sha256(endpoint.encode("utf-8")).digest(),
        )

    def collect_evidence(self, nonce: bytes) -> Evidence:
        self.log.setdefault(f"nonce:{self.hotkey}", []).append(nonce)
        self.evidence_calls += 1
        if self.evidence_calls <= self.spec.evidence_failures:
            raise OSError("evidence unavailable")
        return Evidence(
            kind=self.spec.evidence_kind,
            quote=f"chip:{self.spec.chip}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
            cert_chain=[b"chain"],
            report_data_version=1 if self.spec.legacy_evidence else 2,
            channel_binding=None if self.spec.legacy_evidence else self.binding,
        )

    def confirm_channel_binding(self, evidence: Evidence) -> ChannelBinding:
        if evidence.channel_binding != self.binding:
            raise RuntimeError("test channel binding mismatch")
        if self.spec.channel_mismatch:
            return ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, b"x" * 32)
        return self.binding

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        self.log.setdefault(f"sat:{self.hotkey}", []).append(item.challenge_id)
        self.sat_calls += 1
        if self.sat_calls <= self.spec.sat_failures:
            raise OSError("SAT unavailable")
        assignment = solve_sat(item.instance)
        assert assignment is not None
        owner = "wrong-owner" if self.spec.invalid_sat else self.hotkey
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=10**300,
            challenge_id=item.challenge_id,
            assigned_hotkey=owner,
        )


class FakeFactory:
    def __init__(self, specs: dict[str, MinerSpec]) -> None:
        self.specs = specs
        self.log: dict[str, list] = {}

    def __call__(self, endpoint: str, hotkey: str, **_kwargs: object) -> FakeClient:
        spec = self.specs.get(endpoint)
        if spec is None:
            raise OSError("unreachable")
        return FakeClient(endpoint, hotkey, spec, self.log)


def verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    assert evidence.nonce == nonce
    chip = evidence.quote.decode().removeprefix("chip:")
    return Attested(
        Tier.CC_CPU_TDX,
        chip,
        "measurement",
        1,
        "VERIFIED",
        assurance=attestation_claims(evidence.quote, policy),
    )


setattr(verifier, "production_ready", True)


def production_policy() -> Policy:
    policy = Policy(
        allowed_measurements={"measurement"},
        tdx_strict=True,
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
        registry_profile_ids=("cpu-tdx-v1",),
    )
    object.__setattr__(policy, "_registry_verified", True)
    object.__setattr__(policy, "_registry_valid_from", datetime.now(UTC) - timedelta(days=1))
    object.__setattr__(policy, "_registry_valid_until", datetime.now(UTC) + timedelta(days=1))
    return policy


def make_runtime(
    tmp_path: Path,
    enrollments: list[tuple[str, str]],
    specs: dict[str, MinerSpec],
    *,
    ledger: Ledger | None = None,
    poster: object | None = None,
    attempts: int = 2,
    nonce_factory=None,
    policy: Policy | None = None,
    receipt_issuer: ReceiptIssuer | None = None,
    registry_clock: Callable[[], datetime] | None = None,
) -> tuple[ConfidentialRuntime, Ledger, FakeFactory]:
    if registry_clock is None:
        registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    else:
        registry = RegistryStore(
            str(tmp_path / "registry.sqlite"),
            clock=registry_clock,
        )
    for hotkey, endpoint in enrollments:
        registry.enroll(hotkey, endpoint)
    actual_ledger = ledger or Ledger(tmp_path / "ledger.sqlite")
    factory = FakeFactory(specs)
    runtime = ConfidentialRuntime(
        registry,
        actual_ledger,
        policy or Policy(allowed_measurements={"measurement"}),
        poster,  # type: ignore[arg-type]
        verifier=verifier,
        nonce_factory=nonce_factory or issue_nonce,
        remote_factory=factory,
        config=RuntimeConfig(
            miner_attempts=attempts,
            max_workers=4,
            production_mode=False,
            allow_insecure_http_for_tests=True,
        ),
        receipt_issuer=receipt_issuer,
    )
    return runtime, actual_ledger, factory


def default_specs(**miners: MinerSpec) -> dict[str, MinerSpec]:
    specs = {CANARY.endpoint_url: MinerSpec("canary-chip")}
    for endpoint, spec in miners.items():
        specs[f"http://127.0.0.1:{endpoint}"] = spec
    return specs


def test_canary_failure_creates_no_epoch(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], {})
    with pytest.raises(RuntimeError, match="canary attestation failed"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_endpoint_collision_creates_no_epoch(tmp_path: Path) -> None:
    specs = {CANARY.endpoint_url: MinerSpec("chip")}
    runtime, ledger, _ = make_runtime(tmp_path, [("miner", CANARY.endpoint_url)], specs)
    with pytest.raises(RuntimeError, match="dedicated"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_collision_is_rejected_even_when_enrollment_is_duplicated(tmp_path: Path) -> None:
    specs = {CANARY.endpoint_url: MinerSpec("chip")}
    runtime, ledger, _ = make_runtime(
        tmp_path,
        [("a", CANARY.endpoint_url), ("b", CANARY.endpoint_url + "/")],
        specs,
    )
    with pytest.raises(RuntimeError, match="dedicated"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_chip_collision_at_distinct_endpoint_creates_no_epoch(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("canary-chip")})
    runtime, ledger, factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
    )
    with pytest.raises(RuntimeError, match="shares the dedicated canary TDX chip"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None
    assert ledger.get_epoch(1) is None
    assert "nonce:miner" in factory.log
    assert "sat:canary" in factory.log
    assert "sat:miner" not in factory.log


def _production_runtime(
    tmp_path: Path,
    *,
    enrolled_token: str | None,
    monkeypatch,
) -> tuple[ConfidentialRuntime, Ledger, FakeFactory]:
    registry = RegistryStore(str(tmp_path / "production-registry.sqlite"))
    registry.enroll("miner", "https://1.1.1.1:9001")
    ledger = Ledger(tmp_path / "production-ledger.sqlite")
    specs = {
        "https://8.8.8.8:9000": MinerSpec("canary-chip"),
        "https://1.1.1.1:9001": MinerSpec("miner-chip"),
    }
    factory = FakeFactory(specs)
    policy = production_policy()
    monkeypatch.setattr(runtime_module, "verify", verifier)
    monkeypatch.setattr(runtime_module, "preflight_tdx_verifier", lambda _policy: None)
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        policy,
        token_provider=lambda _hotkey: enrolled_token,
        policy_refresher=lambda: policy,
        verifier=verifier,
        remote_factory=factory,
        config=RuntimeConfig(production_mode=True),
    )
    return runtime, ledger, factory


def test_production_missing_canary_token_fails_before_network_or_epoch(
    tmp_path: Path, monkeypatch
) -> None:
    runtime, ledger, factory = _production_runtime(
        tmp_path, enrolled_token="miner-token", monkeypatch=monkeypatch
    )
    canary = MinerTarget("canary", "https://8.8.8.8:9000")
    with pytest.raises(ValueError, match="bearer token"):
        runtime.run_epoch(1, canary)
    assert factory.log == {}
    assert ledger.blocking_epoch() is None


def test_production_runtime_rejects_unsigned_or_compatibility_policy(tmp_path: Path) -> None:
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with pytest.raises(ValueError, match="strict signed CPU policy"):
        ConfidentialRuntime(
            registry,
            ledger,
            Policy(allowed_measurements={"measurement"}),
            verifier=verifier,
            config=RuntimeConfig(production_mode=True),
        )


def test_production_runtime_rejects_forged_registry_metadata(tmp_path: Path) -> None:
    forged = Policy(
        allowed_measurements={"measurement"},
        tdx_strict=True,
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
        registry_profile_ids=("cpu-tdx-v1",),
    )
    assert forged.production_ready_for_tdx is False
    with pytest.raises(ValueError, match="strict signed CPU policy"):
        ConfidentialRuntime(
            RegistryStore(str(tmp_path / "registry.sqlite")),
            Ledger(tmp_path / "ledger.sqlite"),
            forged,
            verifier=verifier,
            config=RuntimeConfig(production_mode=True),
        )


def test_production_runtime_refreshes_policy_and_rejects_mid_epoch_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    initial = production_policy()
    replacement = production_policy()
    object.__setattr__(replacement, "_registry_valid_from", initial._registry_valid_from)
    object.__setattr__(replacement, "_registry_valid_until", initial._registry_valid_until)
    object.__setattr__(replacement, "registry_profile_ids", ("cpu-tdx-v2",))
    object.__setattr__(replacement, "allowed_measurements", frozenset({"replacement"}))
    factory = FakeFactory({"https://8.8.8.8:9000": MinerSpec("canary")})
    monkeypatch.setattr(runtime_module, "preflight_tdx_verifier", lambda _policy: None)
    runtime = ConfidentialRuntime(
        RegistryStore(str(tmp_path / "registry.sqlite")),
        Ledger(tmp_path / "ledger.sqlite"),
        initial,
        policy_refresher=lambda: replacement,
        remote_factory=factory,
        config=RuntimeConfig(production_mode=True),
    )
    runtime._active_policy_authority = initial.registry_authority_identity

    with pytest.raises(RuntimeError, match="changed during the active epoch"):
        runtime.check_canary(MinerTarget("canary", "https://8.8.8.8:9000", "canary-token"))
    assert factory.log == {}


def test_production_runtime_rejects_custom_verifier_escape_hatch(tmp_path: Path) -> None:
    policy = production_policy()
    with pytest.raises(ValueError, match="pinned TDX verifier"):
        ConfidentialRuntime(
            RegistryStore(str(tmp_path / "registry.sqlite")),
            Ledger(tmp_path / "ledger.sqlite"),
            policy,
            policy_refresher=lambda: policy,
            verifier=verifier,
            config=RuntimeConfig(production_mode=True),
        )


def test_production_runtime_requires_live_policy_refresher(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="live policy registry refresher"):
        ConfidentialRuntime(
            RegistryStore(str(tmp_path / "registry.sqlite")),
            Ledger(tmp_path / "ledger.sqlite"),
            production_policy(),
            config=RuntimeConfig(production_mode=True),
        )


def test_recovery_runtime_cannot_be_reused_for_admission(tmp_path: Path) -> None:
    runtime = ConfidentialRuntime(
        RegistryStore(str(tmp_path / "registry.sqlite")),
        Ledger(tmp_path / "ledger.sqlite"),
        Policy(),
        config=RuntimeConfig(production_mode=True, admission_enabled=False),
    )
    with pytest.raises(RuntimeError, match="admission is disabled"):
        runtime.check_canary(MinerTarget("canary", "https://8.8.8.8", "token"))


def test_production_missing_enrollment_token_fails_before_network_or_epoch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime, ledger, factory = _production_runtime(
        tmp_path, enrolled_token=None, monkeypatch=monkeypatch
    )
    canary = MinerTarget("canary", "https://8.8.8.8:9000", "canary-token")
    with pytest.raises(RuntimeError, match="authentication is required"):
        runtime.run_epoch(1, canary)
    assert factory.log == {}
    assert ledger.blocking_epoch() is None


def test_production_authenticated_targets_complete(tmp_path: Path, monkeypatch) -> None:
    runtime, _, factory = _production_runtime(
        tmp_path, enrolled_token="miner-token", monkeypatch=monkeypatch
    )
    canary = MinerTarget("canary", "https://8.8.8.8:9000", "canary-token")
    run = runtime.run_epoch(1, canary)
    assert run.status == "complete"
    assert run.scores["miner"] == 1.0
    assert "nonce:canary" in factory.log and "nonce:miner" in factory.log


def test_two_unique_tdx_miners_complete_normalized(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a"), "9002": MinerSpec("b")})
    runtime, _, _ = make_runtime(
        tmp_path,
        [("miner-a", "http://127.0.0.1:9001"), ("miner-b", "http://127.0.0.1:9002")],
        specs,
    )
    run = runtime.run_epoch(7, CANARY)
    assert run.status == "complete"
    assert run.published is False
    assert dict(run.scores) == {"miner-a": 1.0, "miner-b": 1.0}
    assert {outcome.status for outcome in run.outcomes} == {"verified"}
    assert all(outcome.work_units == 20 for outcome in run.outcomes)


@pytest.mark.parametrize(
    ("invalid_sat", "expected_outcome", "expected_claim", "expected_units"),
    [
        (False, "verified", "passed", "20"),
        (True, "sat_failed", "failed", "0"),
    ],
)
def test_runtime_atomically_persists_offline_verifiable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_sat: bool,
    expected_outcome: str,
    expected_claim: str,
    expected_units: str,
) -> None:
    from tests.test_receipt import ISSUED, ISSUED_TEXT, RECEIPT_SEED_1, _snapshot

    snapshot = _snapshot()
    policy = snapshot.to_policy(at=ISSUED)
    issuer = ReceiptIssuer(
        snapshot,
        "receipt-test-1",
        RECEIPT_SEED_1,
        clock=lambda: ISSUED,
    )
    monkeypatch.setattr("cathedral.assurance.verified_at_now", lambda: ISSUED_TEXT)
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=invalid_sat)})
    runtime, ledger, _ = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        policy=policy,
        receipt_issuer=issuer,
        registry_clock=lambda: ISSUED,
    )

    def registry_verifier(evidence: Evidence, nonce: bytes, active: Policy) -> Attested:
        assert evidence.nonce == nonce
        return Attested(
            Tier.CC_CPU_TDX,
            evidence.quote.decode().removeprefix("chip:"),
            "tdx-measurement-sha256:sample-v1",
            1,
            tcb_status="UpToDate",
            advisory_ids=(),
            debug_enabled=False,
            collateral_current=True,
            tcb_svn="01" * 16,
            policy_mode="strict",
            assurance=attestation_claims(
                evidence.quote,
                active,
                verified_at=ISSUED_TEXT,
            ),
        )

    runtime.verifier = registry_verifier
    run = runtime.run_epoch(11, CANARY)
    outcome = next(item for item in run.outcomes if item.hotkey == "miner")
    stored = ledger.receipt_for_challenge(outcome.challenge_id or "")

    assert stored is not None
    verified = verify_receipt(stored["receipt_body"], snapshot)
    assert stored["receipt_id"] == verified.receipt_id
    assert stored["receipt_digest"] == verified.receipt_digest
    assert verified.document["epoch_id"] == run.epoch_id
    assert verified.document["source_epoch"] == 11
    assert verified.document["subject_hotkey"] == "miner"
    assert verified.document["work"]["challenge_id"] == outcome.challenge_id
    assert outcome.status == expected_outcome
    assert verified.document["work"]["status"] == expected_claim
    assert verified.document["work"]["work_units"] == expected_units


def test_hardware_pass_with_work_failure_is_explicit_zero(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=True)})
    runtime, _, _ = make_runtime(tmp_path, [("miner", "http://127.0.0.1:9001")], specs)

    run = runtime.run_epoch(1, CANARY)
    outcome = next(item for item in run.outcomes if item.hotkey == "miner")

    assert outcome.score == 0.0
    assert outcome.assurance is not None
    assert outcome.assurance.hardware.status is ClaimStatus.PASSED
    assert outcome.assurance.software.status is ClaimStatus.PASSED
    assert outcome.assurance.channel.status is ClaimStatus.PASSED
    assert outcome.assurance.work.status is ClaimStatus.FAILED


def test_runtime_rejects_legacy_verified_flag_without_typed_claims(tmp_path: Path) -> None:
    runtime, ledger, factory = make_runtime(tmp_path, [], default_specs())

    def legacy_verifier(evidence: Evidence, nonce: bytes, _policy: Policy) -> Attested:
        assert evidence.nonce == nonce
        return Attested(Tier.CC_CPU_TDX, "chip", "measurement", 1, "VERIFIED")

    runtime.verifier = legacy_verifier

    with pytest.raises(RuntimeError, match="hardware and software admission claims"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None
    assert "sat:canary" not in factory.log


def test_channel_mismatch_never_dispatches_work_or_admits(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", channel_mismatch=True)})
    runtime, _, factory = make_runtime(tmp_path, [("miner", "http://127.0.0.1:9001")], specs)

    run = runtime.run_epoch(1, CANARY)
    outcome = next(item for item in run.outcomes if item.hotkey == "miner")

    assert outcome.status == "attestation_failed"
    assert outcome.score == 0.0
    assert "sat:miner" not in factory.log


def test_production_rejects_legacy_report_data_before_work(tmp_path: Path, monkeypatch) -> None:
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    ledger = Ledger(tmp_path / "ledger.sqlite")
    factory = FakeFactory({"https://8.8.8.8:9000": MinerSpec("canary", legacy_evidence=True)})
    policy = production_policy()
    monkeypatch.setattr(runtime_module, "verify", verifier)
    monkeypatch.setattr(runtime_module, "preflight_tdx_verifier", lambda _policy: None)
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        policy,
        policy_refresher=lambda: policy,
        verifier=verifier,
        remote_factory=factory,
        config=RuntimeConfig(production_mode=True),
    )

    with pytest.raises(RuntimeError, match="report data v2"):
        runtime.check_canary(MinerTarget("canary", "https://8.8.8.8:9000", "canary-token"))
    assert "sat:canary" not in factory.log


def test_invalid_untrusted_certificate_still_produces_failed_work_claim():
    policy = Policy(allowed_measurements={"measurement"})
    attested = Attested(
        Tier.CC_CPU_TDX,
        "chip",
        "measurement",
        1,
        assurance=attestation_claims(b"quote", policy),
    )
    item = SatLane().dispatch("miner", budget=1)
    assert isinstance(item, SatWorkItem)
    certificate = SatCertificate(
        satisfiable=False,
        assignment=None,
        work_units=float("nan"),
        challenge_id=item.challenge_id,
        assigned_hotkey="miner",
    )

    claims = _work_assurance(attested, item, certificate, passed=False)

    assert claims.work.status is ClaimStatus.FAILED
    assert claims.work.policy_digest == SAT_WORK_POLICY_DIGEST
    assert claims.work.policy_digest != claims.software.policy_digest


def test_evidence_audit_digest_commits_to_report_version_and_channel_binding():
    common = dict(
        kind=EvidenceKind.TDX,
        quote=b"quote",
        nonce=b"n" * 32,
        miner_hotkey="miner",
    )
    legacy = Evidence(**common)
    first = Evidence(
        **common,
        report_data_version=2,
        channel_binding=ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32),
    )
    second = Evidence(
        **common,
        report_data_version=2,
        channel_binding=ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"b" * 32),
    )

    assert (
        len(
            {
                _evidence_digest(legacy),
                _evidence_digest(first),
                _evidence_digest(second),
            }
        )
        == 3
    )


def test_runtime_persists_strict_attestation_policy_mode(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a")})
    runtime, ledger, _ = make_runtime(tmp_path, [("miner-a", "http://127.0.0.1:9001")], specs)

    def strict_verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested:
        assert evidence.nonce == nonce
        chip = evidence.quote.decode().removeprefix("chip:")
        return Attested(
            Tier.CC_CPU_TDX,
            chip,
            "measurement",
            1,
            policy_mode="strict",
            assurance=attestation_claims(evidence.quote, policy),
        )

    runtime.verifier = strict_verifier
    run = runtime.run_epoch(7, CANARY)
    payload = json.loads(ledger.report_bytes(run.epoch_id))

    assert payload["metadata"]["attestation_policy_modes"] == ["strict"]


def test_duplicate_endpoint_excludes_all_claimants(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("unused")})
    endpoint = "http://127.0.0.1:9001"
    runtime, _, factory = make_runtime(tmp_path, [("a", endpoint), ("b", endpoint + "/")], specs)
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"a": 0.0, "b": 0.0}
    assert {outcome.status for outcome in run.outcomes} == {"duplicate_endpoint"}
    assert "nonce:a" not in factory.log and "nonce:b" not in factory.log


@pytest.mark.parametrize("order", [("a", "b"), ("b", "a")])
def test_duplicate_chip_excludes_all_independent_of_order(
    tmp_path: Path, order: tuple[str, str]
) -> None:
    endpoints = {"a": "http://127.0.0.1:9001", "b": "http://127.0.0.1:9002"}
    specs = default_specs(**{"9001": MinerSpec("same"), "9002": MinerSpec("same")})
    runtime, ledger, _ = make_runtime(
        tmp_path, [(hotkey, endpoints[hotkey]) for hotkey in order], specs
    )
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"a": 0.0, "b": 0.0}
    assert {outcome.status for outcome in run.outcomes} == {"duplicate_chip"}
    assert ledger.attested_hotkeys(run.epoch_id) == frozenset()


def test_chip_rotation_to_new_hotkey_is_blocked_within_ttl(tmp_path: Path) -> None:
    """A physical chip verified for hotkey "a" in one epoch must not be
    admitted under a different hotkey "b" in a later epoch while the first
    binding is still effective — even though the two hotkeys never attest
    within the same epoch, so the same-epoch duplicate-chip check alone
    cannot see the collision.
    """

    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    registry.enroll("a", "http://127.0.0.1:9001")
    ledger = Ledger(tmp_path / "ledger.sqlite")
    specs = default_specs(**{"9001": MinerSpec("shared-chip")})
    factory = FakeFactory(specs)
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        Policy(allowed_measurements={"measurement"}),
        poster=RecordingPoster(),
        verifier=verifier,
        remote_factory=factory,
        config=RuntimeConfig(
            max_workers=4,
            production_mode=False,
            allow_insecure_http_for_tests=True,
        ),
    )

    first = runtime.run_epoch(1, CANARY, publish=True)
    assert dict(first.scores) == {"a": 1.0}
    assert {outcome.status for outcome in first.outcomes} == {"verified"}
    assert first.published is True

    # "a"'s worker goes offline; the same physical chip now serves "b" at a
    # freshly enrolled endpoint.
    registry.enroll("b", "http://127.0.0.1:9002")
    specs["http://127.0.0.1:9002"] = MinerSpec("shared-chip")
    del specs["http://127.0.0.1:9001"]

    second = runtime.run_epoch(2, CANARY)
    assert dict(second.scores) == {"a": 0.0, "b": 0.0}
    statuses = {outcome.hotkey: outcome.status for outcome in second.outcomes}
    assert statuses["a"] == "attestation_failed"
    assert statuses["b"] == "chip_rotation_conflict"
    assert "already bound to hotkey a" in (
        next(o.error for o in second.outcomes if o.hotkey == "b") or ""
    )


def test_invalid_miner_is_zero_while_peer_succeeds(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("good")})
    runtime, _, _ = make_runtime(
        tmp_path,
        [("bad", "http://127.0.0.1:9999"), ("good", "http://127.0.0.1:9001")],
        specs,
    )
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"bad": 0.0, "good": 1.0}
    assert {outcome.hotkey: outcome.status for outcome in run.outcomes} == {
        "bad": "attestation_failed",
        "good": "verified",
    }


def test_retries_use_fresh_evidence_nonce_and_same_sat_challenge(tmp_path: Path) -> None:
    counter = iter(range(20))

    def nonces() -> bytes:
        return next(counter).to_bytes(32, "big")

    specs = default_specs(**{"9001": MinerSpec("a", evidence_failures=1, sat_failures=1)})
    runtime, _, factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        nonce_factory=nonces,
    )
    run = runtime.run_epoch(1, CANARY)
    assert run.scores["miner"] == 1.0
    assert len(set(factory.log["nonce:miner"])) == 2
    assert len(factory.log["sat:miner"]) == 2
    assert len(set(factory.log["sat:miner"])) == 1


def test_exact_owner_rejection_completes_as_zero(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=True)})
    runtime, _, _ = make_runtime(tmp_path, [("miner", "http://127.0.0.1:9001")], specs)
    run = runtime.run_epoch(1, CANARY)
    assert run.scores["miner"] == 0.0
    assert run.outcomes[0].status == "sat_failed"


def test_runtime_exception_aborts_and_same_source_retries(tmp_path: Path, monkeypatch) -> None:
    specs = default_specs(**{"9001": MinerSpec("a")})
    runtime, ledger, _ = make_runtime(tmp_path, [("miner", "http://127.0.0.1:9001")], specs)
    original = ledger.complete_epoch

    def explode(*_args, **_kwargs):
        raise RuntimeError("freeze failed")

    monkeypatch.setattr(ledger, "complete_epoch", explode)
    with pytest.raises(RuntimeError, match="freeze failed"):
        runtime.run_epoch(3, CANARY)
    assert ledger.get_epoch(1)["status"] == "aborted"

    monkeypatch.setattr(ledger, "complete_epoch", original)
    retried = runtime.run_epoch(3, CANARY)
    assert retried.status == "complete"
    assert retried.source_epoch == 3


def test_unresolved_challenge_cannot_complete() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    ledger.issue_challenge("challenge", "miner", epoch_id)
    with pytest.raises(LedgerError, match="unresolved"):
        ledger.complete_epoch(epoch_id, {"miner"})


@pytest.mark.parametrize("enrollments", [[], [("miner", "http://127.0.0.1:9001")]])
def test_empty_and_healthy_no_work_snapshots_complete(
    tmp_path: Path, enrollments: list[tuple[str, str]]
) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=True)})
    runtime, ledger, _ = make_runtime(tmp_path, enrollments, specs)
    run = runtime.run_epoch(1, CANARY)
    assert run.status == "complete"
    assert all(score == 0 for score in run.scores.values())
    assert b'"complete":true' in ledger.report_bytes(run.epoch_id)


class RecordingPoster:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.bodies: list[bytes] = []

    def post(self, body: bytes) -> dict[str, str]:
        self.bodies.append(body)
        if self.fail:
            raise OSError("ambiguous publication failure")
        return {"status": "accepted"}


class SignedRecordingPoster(RecordingPoster):
    def __init__(self, secret: bytes) -> None:
        super().__init__()
        self.secret = secret
        self.signatures: list[str] = []

    def post(self, body: bytes) -> dict[str, str]:
        self.signatures.append(hmac.new(self.secret, body, hashlib.sha256).hexdigest())
        return super().post(body)


def test_policy_revocation_publishes_signed_positive_to_explicit_zero_without_network(
    tmp_path: Path,
) -> None:
    poster = SignedRecordingPoster(b"score-secret")
    specs = default_specs(**{"9001": MinerSpec("a")})
    runtime, ledger, factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        poster=poster,
    )

    positive = runtime.run_epoch(1, CANARY, publish=True)
    worker_calls = len(factory.log["nonce:miner"])
    assert positive.scores["miner"] == 1.0

    runtime.policy = Policy(allowed_measurements={"replacement-measurement"})
    zero = runtime.run_epoch(2, CANARY, publish=True)
    zero_report = json.loads(ledger.report_bytes(zero.epoch_id))
    lifecycle = zero_report["metadata"]["worker_lifecycle"]

    assert zero.scores["miner"] == 0.0
    assert {outcome.status for outcome in zero.outcomes} == {"revoked"}
    assert len(factory.log["nonce:miner"]) == worker_calls
    assert lifecycle == [
        {
            "event_id": lifecycle[0]["event_id"],
            "evidence_expires_at": lifecycle[0]["evidence_expires_at"],
            "generation": 1,
            "hotkey": "miner",
            "reason": "policy_revoked",
            "revision": 3,
            "snapshot_at": lifecycle[0]["snapshot_at"],
            "state": "revoked",
        }
    ]
    assert poster.bodies == [
        ledger.report_bytes(positive.epoch_id),
        ledger.report_bytes(zero.epoch_id),
    ]
    assert poster.signatures == [
        hmac.new(poster.secret, body, hashlib.sha256).hexdigest() for body in poster.bodies
    ]


def test_dry_run_publish_failure_and_byte_identical_retry(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a")})
    poster = RecordingPoster(fail=True)
    runtime, ledger, _ = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        poster=poster,
    )
    run = runtime.run_epoch(1, CANARY)
    assert poster.bodies == []

    with pytest.raises(OSError, match="ambiguous"):
        runtime.publish_completed(run.epoch_id)
    assert ledger.get_epoch(run.epoch_id)["status"] == "complete"
    frozen = ledger.report_bytes(run.epoch_id)

    poster.fail = False
    runtime.publish_completed(run.epoch_id)
    assert ledger.get_epoch(run.epoch_id)["status"] == "published"
    assert poster.bodies == [frozen, frozen]
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.publish_completed(run.epoch_id)


def test_restart_status_and_explicit_abort(tmp_path: Path) -> None:
    db = tmp_path / "ledger.sqlite"
    first = Ledger(db)
    epoch_id = first.begin_epoch(9)
    first.close()
    runtime, reopened, _ = make_runtime(tmp_path, [], default_specs(), ledger=Ledger(db))
    assert runtime.status()["blocking_epoch"]["status"] == "running"
    assert runtime.abort_running() == epoch_id
    assert reopened.get_epoch(epoch_id)["status"] == "aborted"


def test_abandon_completed_unblocks_begin_epoch_and_is_audited(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], default_specs())
    run = runtime.run_epoch(1, CANARY)
    assert run.status == "complete"

    with pytest.raises(LedgerError, match="publish it"):
        ledger.begin_epoch(2)

    epoch_id = runtime.abandon_completed(run.epoch_id, "report too old for first ingest")
    assert epoch_id == run.epoch_id
    row = ledger.get_epoch(epoch_id)
    assert row["status"] == "abandoned"
    assert row["abandon_reason"] == "report too old for first ingest"
    assert row["abandoned_at"] is not None

    # begin_epoch is unblocked; a later source epoch can proceed.
    next_run = runtime.run_epoch(2, CANARY)
    assert next_run.status == "complete"


def test_abandon_completed_requires_exact_blocking_epoch(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], default_specs())
    run = runtime.run_epoch(1, CANARY)
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.abandon_completed(run.epoch_id + 1, "reason")


def test_abandon_completed_rejects_a_running_epoch(tmp_path: Path) -> None:
    db = tmp_path / "ledger.sqlite"
    first = Ledger(db)
    epoch_id = first.begin_epoch(1)
    first.close()
    runtime, _, _ = make_runtime(tmp_path, [], default_specs(), ledger=Ledger(db))
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.abandon_completed(epoch_id, "reason")


def test_runtime_has_no_forbidden_scorer_path_imports_or_calls() -> None:
    path = Path(__file__).parents[1] / "cathedral" / "runtime.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {"attested_epoch", "apply_routing", "bittensor", "set_weights"}
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").lower())
            imported.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id.lower())
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr.lower())
    assert not any(any(name in value for name in forbidden) for value in imported)
    assert forbidden.isdisjoint(called)


def test_sat_lane_still_rejects_wrong_owner() -> None:
    lane = SatLane(namespace="owner-test")
    item = lane.dispatch("expected", 1)
    assert isinstance(item, SatWorkItem)
    cert = SatCertificate(
        True,
        solve_sat(item.instance),
        20,
        item.challenge_id,
        "other",
    )
    assert lane.verify(item, cert) is None
