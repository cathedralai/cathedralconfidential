"""Composite TDX plus NVIDIA GPU evidence, policy, identity, and score gates."""

from __future__ import annotations

import base64
import concurrent.futures
import io
import json
import shlex
import shutil
import sqlite3
import struct
import sys
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

import pytest

from cathedral.assurance import ClaimStatus, attestation_claims, with_verified_channel
from cathedral.attest import collect_gpu_cc
from cathedral.channel import application_key_binding
from cathedral.common import (
    Attested,
    Evidence,
    EvidenceKind,
    MAX_COMPOSITE_JWT_BYTES,
    MAX_EVIDENCE_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_COMPONENTS,
    MAX_EVIDENCE_COMPONENT_JSON_OVERHEAD,
    MAX_EVIDENCE_QUOTE_BYTES,
    MAX_EVIDENCE_RESPONSE_BODY,
    MAX_GPU_EVIDENCE_CONCURRENCY,
    MAX_GPU_EVIDENCE_DECODED_BYTES,
    MAX_GPU_EVIDENCE_IN_FLIGHT_BYTES,
    MAX_GPU_EVIDENCE_RESERVATION_BYTES,
    MAX_GPU_EVIDENCE_WORKING_SET_BYTES,
    MAX_GPU_VERIFIER_REQUEST_BYTES,
    Policy,
    Tier,
)
from cathedral.enroll import RegistryStore
from cathedral.gpu import (
    GPU_COLLECTION_SCHEMA,
    GPU_PREFLIGHT_SCHEMA,
    GPU_VERIFIER_RESULT_SCHEMA,
    MAX_GPU_COLLECTOR_OUTPUT_BYTES,
    MAX_GPU_VERIFIER_INPUT_BYTES,
    ExternalGpuCollector,
    ExternalGpuVerifier,
    GpuAttestationError,
    GpuIdentityRegistry,
    GpuProfile,
    gpu_challenge,
    gpu_host_session_digest,
    gpu_identity_policy_digest,
    gpu_lifecycle_measurement,
    gpu_lifecycle_measurements,
    gpu_profile_authority,
    gpu_profile_from_registry,
    gpu_score_eligible,
    collect_gpu_from_env,
    _is_static_tdx_elf,
    tdx_component_binding_digest,
    verify_composite_gpu,
)
from cathedral.lanes.sat import SatLane
from cathedral.ledger import Ledger
from cathedral.lifecycle import LifecycleError, LifecycleReason, WorkerLifecycleState
from cathedral.policy_registry import PolicyProfile, PolicyRegistrySnapshot
from cathedral.prober import probe_once, verify_cc_evidence_bundle
from cathedral.runtime import ConfidentialRuntime, MinerTarget, RuntimeConfig
from cathedral.workload import (
    ExternalVerifierConfig,
    SignatureVerifierError,
)


NOW = datetime(2026, 7, 17, 15, 0, tzinfo=UTC)
NONCE = b"n" * 32
HOTKEY = "gpu-worker-hotkey"
GPU_1 = "GPU-11111111-1111-4111-8111-111111111111"
GPU_2 = "GPU-22222222-2222-4222-8222-222222222222"
_TRUE_EXECUTABLE = shutil.which("true")
assert _TRUE_EXECUTABLE is not None
NATIVE_TEST_EXECUTABLE = str(Path(_TRUE_EXECUTABLE).resolve())
TEST_VERIFIER_CONFIG = ExternalVerifierConfig(
    (NATIVE_TEST_EXECUTABLE,),
    implementation_artifacts=(NATIVE_TEST_EXECUTABLE,),
)
VERIFIER_DIGEST = ExternalGpuVerifier(
    TEST_VERIFIER_CONFIG,
    production_mode=False,
).implementation_digest


def _production_identity_paths(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    database_parent = tmp_path / "identity-database"
    anchor_parent = tmp_path / "identity-anchor"
    database_parent.mkdir(mode=0o700)
    anchor_parent.mkdir(mode=0o700)
    database_parent.chmod(0o700)
    anchor_parent.chmod(0o700)
    return (
        database_parent / "gpu-identities.sqlite",
        anchor_parent / "generation.anchor",
    )


def _binding(seed: bytes = b"k" * 32):
    return application_key_binding(seed)


def _profile(**overrides) -> GpuProfile:
    values = {
        "profile_id": "tdx-h100-pcie-2-v1",
        "expected_device_identity_digests": frozenset(
            {gpu_identity_policy_digest(GPU_1), gpu_identity_policy_digest(GPU_2)}
        ),
        "allowed_models": frozenset({"NVIDIA-H100-80GB-HBM3"}),
        "allowed_cc_modes": frozenset({"CC-On"}),
        "allowed_drivers": frozenset({"550.90.07"}),
        "allowed_vbios": frozenset({"96.00.5E.00.01"}),
        "allowed_security_states": frozenset({"Secure"}),
        "allowed_cpu_measurements": frozenset({"cpu-measurement"}),
        "verifier_digest": VERIFIER_DIGEST,
        "active": True,
    }
    values.update(overrides)
    return GpuProfile(**values)


def _gpu_evidence(*, nonce: bytes = NONCE, hotkey: str = HOTKEY, binding=None) -> Evidence:
    return Evidence(
        kind=EvidenceKind.GPU_CC,
        quote=b"vendor-gpu-attestation-bundle",
        cert_chain=[b"vendor-cert"],
        nonce=nonce,
        miner_hotkey=hotkey,
        composite_jwt=None,
        report_data_version=2,
        channel_binding=binding or _binding(),
    )


def _tdx_evidence(*, nonce: bytes = NONCE, hotkey: str = HOTKEY, binding=None) -> Evidence:
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=b"tdx-quote",
        nonce=nonce,
        miner_hotkey=hotkey,
        report_data_version=2,
        channel_binding=binding or _binding(),
    )


def _device(gpu_uuid: str, **overrides) -> dict[str, object]:
    values: dict[str, object] = {
        "gpu_uuid": gpu_uuid,
        "model": "NVIDIA-H100-80GB-HBM3",
        "cc_mode": "CC-On",
        "driver": "550.90.07",
        "vbios": "96.00.5E.00.01",
        "security_state": "Secure",
        "evidence_verified": True,
    }
    values.update(overrides)
    return values


def _verifier_result(
    evidence: Evidence,
    profile: GpuProfile,
    *,
    tdx_evidence: Evidence | None = None,
    tdx_verdict: Attested | None = None,
    **overrides,
):
    assert evidence.channel_binding is not None
    tdx_evidence = tdx_evidence or _tdx_evidence(
        nonce=evidence.nonce,
        hotkey=evidence.miner_hotkey,
        binding=evidence.channel_binding,
    )
    tdx_verdict = tdx_verdict or _cpu_attested(
        Policy(allowed_measurements=frozenset({"cpu-measurement"})),
        evidence.channel_binding,
    )
    tdx_digest = tdx_component_binding_digest(tdx_evidence, tdx_verdict)
    values = {
        "schema": GPU_VERIFIER_RESULT_SCHEMA,
        "vendor_verified": True,
        "host_session_verified": True,
        "composite_binding_verified": True,
        "challenge_digest": "sha256:"
        + gpu_challenge(evidence.nonce, evidence.miner_hotkey, evidence.channel_binding).hex(),
        "host_session_digest": gpu_host_session_digest(
            evidence.nonce, evidence.miner_hotkey, evidence.channel_binding
        ),
        "profile_digest": profile.digest,
        "verifier_digest": profile.verifier_digest,
        "cpu_tee": EvidenceKind.TDX.value,
        "tdx_component_digest": tdx_digest,
        "tdx_measurement": tdx_verdict.measurement,
        "tdx_platform_id": tdx_verdict.chip_id,
        "devices": [_device(GPU_1), _device(GPU_2)],
        "topology_metadata": {"reported_links": ["0-1"], "source": "audit-only"},
    }
    values.update(overrides)
    return values


class StaticRunner:
    def __init__(self, result, *, profile=None):
        self.result = result
        self.profile = profile
        self.requests = []

    def _invoke(self, request):
        self.requests.append(request)
        if request.get("operation") == "preflight" and self.profile is not None:
            profile = self.profile
            assert profile is not None
            return {
                "schema": GPU_PREFLIGHT_SCHEMA,
                "profile_digest": profile.digest,
                "verifier_digest": profile.verifier_digest,
                "ready": True,
            }
        return self.result


def _verifier(result, profile=None) -> ExternalGpuVerifier:
    profile = profile or _profile()
    verifier = ExternalGpuVerifier(TEST_VERIFIER_CONFIG, production_mode=False)
    object.__setattr__(verifier, "_runner", StaticRunner(result, profile=profile))
    return verifier


def _cpu_attested(policy: Policy, binding=None) -> Attested:
    binding = binding or _binding()
    claims = with_verified_channel(
        attestation_claims(b"tdx-quote", policy),
        binding.canonical_bytes(),
    )
    return Attested(
        Tier.CC_CPU_TDX,
        "tdx-platform-sha256:" + "1" * 64,
        "cpu-measurement",
        7,
        assurance=claims,
    )


def _verify_gpu(
    verifier: ExternalGpuVerifier,
    evidence: Evidence,
    profile: GpuProfile,
    *,
    tdx_evidence: Evidence | None = None,
    tdx_verdict: Attested | None = None,
):
    assert evidence.channel_binding is not None
    tdx_evidence = tdx_evidence or _tdx_evidence(
        nonce=evidence.nonce,
        hotkey=evidence.miner_hotkey,
        binding=evidence.channel_binding,
    )
    tdx_verdict = tdx_verdict or _cpu_attested(
        Policy(allowed_measurements=frozenset({"cpu-measurement"})),
        evidence.channel_binding,
    )
    return verifier.verify(
        evidence,
        profile,
        tdx_evidence=tdx_evidence,
        tdx_verdict=tdx_verdict,
    )


def _component(evidence: Evidence | None = None, profile: GpuProfile | None = None):
    evidence = evidence or _gpu_evidence()
    profile = profile or _profile()
    return _verify_gpu(
        _verifier(_verifier_result(evidence, profile), profile),
        evidence,
        profile,
    )


def test_gpu_challenge_is_independent_domain_separated_and_binding_sensitive():
    first = gpu_challenge(NONCE, HOTKEY, _binding())
    assert len(first) == 32
    assert first != NONCE
    assert first != gpu_challenge(b"x" * 32, HOTKEY, _binding())
    assert first != gpu_challenge(NONCE, "other-hotkey", _binding())
    assert first != gpu_challenge(NONCE, HOTKEY, _binding(b"z" * 32))


def test_external_collector_returns_bounded_typed_component():
    quote = b"vendor-quote"
    collector = object.__new__(ExternalGpuCollector)
    collector._runner = StaticRunner(
        {
            "schema": GPU_COLLECTION_SCHEMA,
            "quote_b64": base64.b64encode(quote).decode(),
            "cert_chain_b64": [base64.b64encode(b"cert").decode()],
            "composite_jwt": None,
        }
    )
    evidence = collector.collect(NONCE, HOTKEY, _binding())

    assert evidence.kind is EvidenceKind.GPU_CC
    assert evidence.quote == quote
    assert evidence.report_data_version == 2
    assert evidence.channel_binding == _binding()


def test_external_collector_accepts_maximum_wire_envelope(tmp_path: Path, monkeypatch):
    collector = tmp_path / "collector.py"
    collector.write_text(
        "import base64,json,sys\n"
        "json.load(sys.stdin)\n"
        "document={"
        f"'cert_chain_b64':[base64.b64encode(b'c'*{MAX_EVIDENCE_CERTIFICATE_BYTES}).decode() for _ in range({MAX_EVIDENCE_CERTIFICATES})],"
        f"'composite_jwt':'j'*{MAX_COMPOSITE_JWT_BYTES},"
        f"'quote_b64':base64.b64encode(b'q'*{MAX_EVIDENCE_QUOTE_BYTES}).decode(),"
        "'schema':'cathedral_gpu_collection_v1'}\n"
        "sys.stdout.write(json.dumps(document,sort_keys=True,separators=(',',':')))\n"
    )
    monkeypatch.setenv(
        "CATHEDRAL_GPU_COLLECT_CMD",
        shlex.join((sys.executable, str(collector))),
    )

    evidence = collect_gpu_from_env(NONCE, HOTKEY, _binding())

    assert len(evidence.quote) == MAX_EVIDENCE_QUOTE_BYTES
    assert len(evidence.cert_chain) == MAX_EVIDENCE_CERTIFICATES
    assert all(
        len(certificate) == MAX_EVIDENCE_CERTIFICATE_BYTES for certificate in evidence.cert_chain
    )
    assert evidence.composite_jwt == "j" * MAX_COMPOSITE_JWT_BYTES
    assert MAX_GPU_COLLECTOR_OUTPUT_BYTES == 16 * 1024 * 1024


def test_collect_gpu_cc_uses_configured_collector_without_not_implemented(monkeypatch):
    expected = _gpu_evidence()
    monkeypatch.setattr("cathedral.gpu.collect_gpu_from_env", lambda *_args: expected)
    assert collect_gpu_cc(NONCE, HOTKEY, channel_binding=_binding()) is expected


def test_valid_gpu_component_enforces_exact_device_set_and_hides_raw_ids_in_audit():
    component = _component()
    audit = dict(component.audit_dict())

    assert component.identity_set == frozenset({GPU_1, GPU_2})
    assert audit["device_count"] == 2
    assert GPU_1 not in str(audit)
    assert audit["topology_digest"].startswith("sha256:")


def test_gpu_profile_is_selected_from_active_signed_registry_snapshot():
    metadata = MappingProxyType(
        {
            "allowed_cc_modes": ("CC-On",),
            "allowed_cpu_measurements": ("cpu-measurement",),
            "allowed_drivers": ("550.90.07",),
            "allowed_models": ("NVIDIA-H100-80GB-HBM3",),
            "allowed_security_states": ("Secure",),
            "allowed_vbios": ("96.00.5E.00.01",),
            "cpu_kind": EvidenceKind.TDX.value,
            "expected_device_identity_digests": (
                gpu_identity_policy_digest(GPU_1),
                gpu_identity_policy_digest(GPU_2),
            ),
            "verifier_digest": VERIFIER_DIGEST,
        }
    )
    registry_profile = PolicyProfile(
        profile_id="tdx-h100-pcie-2-v1",
        kind="gpu_cc",
        status="active",
        status_changed_at=NOW - timedelta(hours=1),
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
        retire_at=None,
        measurements=(),
        runtime_measurements=(),
        allowed_firmware=(),
        min_tcb=0,
        tdx_allowed_tcb_statuses=(),
        tdx_allowed_advisories=(),
        metadata=metadata,
    )
    snapshot = PolicyRegistrySnapshot(
        release=7,
        generated_at=NOW - timedelta(hours=1),
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
        signing_key_id="policy-key",
        digest="sha256:" + "7" * 64,
        profiles=(registry_profile,),
        receipt_signing_keys=(),
        metadata=MappingProxyType({}),
        canonical_document=b"signed-registry",
    )
    with pytest.raises(GpuAttestationError) as unverified_snapshot:
        gpu_profile_from_registry(snapshot, "tdx-h100-pcie-2-v1", at=NOW)
    assert unverified_snapshot.value.category == "invalid_policy"
    object.__setattr__(snapshot, "_signature_verified", True)

    profile = gpu_profile_from_registry(
        snapshot,
        "tdx-h100-pcie-2-v1",
        at=NOW,
    )

    assert profile.production_ready
    assert profile.registry_release == 7
    assert profile.registry_digest == snapshot.digest
    assert profile.expected_device_identity_digests == frozenset(
        {gpu_identity_policy_digest(GPU_1), gpu_identity_policy_digest(GPU_2)}
    )
    assert GPU_1 not in str(metadata)
    assert profile.production_ready_at(NOW)
    assert not profile.production_ready_at(snapshot.valid_until)
    assert not profile.production_ready_for(
        Policy(registry_release=8, registry_digest="sha256:" + "8" * 64),
        at=NOW,
    )
    forged = _profile(
        registry_release=snapshot.release,
        registry_digest=snapshot.digest,
    )
    assert not forged.production_ready_at(NOW)
    expired = replace(profile)
    object.__setattr__(expired, "registry_valid_from", NOW - timedelta(days=2))
    object.__setattr__(expired, "registry_valid_until", NOW - timedelta(days=1))
    object.__setattr__(expired, "_registry_verified", True)
    with pytest.raises(GpuAttestationError) as expired_error:
        verify_composite_gpu(
            _tdx_evidence(),
            _gpu_evidence(),
            NONCE,
            Policy(
                allowed_measurements=frozenset({"cpu-measurement"}),
                registry_release=snapshot.release,
                registry_digest=snapshot.digest,
            ),
            expired,
            _verifier(_verifier_result(_gpu_evidence(), expired), expired),
        )
    assert expired_error.value.category == "profile_inactive"

    retiring = replace(
        snapshot,
        profiles=(
            replace(
                registry_profile,
                status="retiring",
                retire_at=NOW + timedelta(hours=1),
            ),
        ),
    )
    object.__setattr__(retiring, "_signature_verified", True)
    with pytest.raises(GpuAttestationError) as raised:
        gpu_profile_from_registry(retiring, "tdx-h100-pcie-2-v1", at=NOW)
    assert raised.value.category == "profile_inactive"

    duplicated = replace(
        snapshot,
        profiles=(
            replace(
                registry_profile,
                metadata=MappingProxyType(
                    {
                        **dict(metadata),
                        "expected_device_identity_digests": (
                            gpu_identity_policy_digest(GPU_1),
                            gpu_identity_policy_digest(GPU_1),
                        ),
                    }
                ),
            ),
        ),
    )
    object.__setattr__(duplicated, "_signature_verified", True)
    with pytest.raises(GpuAttestationError) as duplicate_error:
        gpu_profile_from_registry(duplicated, "tdx-h100-pcie-2-v1", at=NOW)
    assert duplicate_error.value.category == "invalid_policy"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model", "NVIDIA-H200"),
        ("cc_mode", "CC-Off"),
        ("driver", "551.00"),
        ("vbios", "unexpected"),
        ("security_state", "Degraded"),
        ("evidence_verified", False),
    ],
)
def test_gpu_policy_rejects_every_vendor_backed_security_property(field, value):
    evidence = _gpu_evidence()
    profile = _profile()
    devices = [_device(GPU_1, **{field: value}), _device(GPU_2)]
    verifier = _verifier(_verifier_result(evidence, profile, devices=devices))

    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(verifier, evidence, profile)

    assert raised.value.category == "gpu_policy_denied"


@pytest.mark.parametrize(
    "devices",
    [
        [_device(GPU_1)],
        [_device(GPU_1), _device("GPU-33333333-3333-4333-8333-333333333333")],
    ],
)
def test_gpu_identity_set_rejects_missing_and_unexpected_devices(devices):
    evidence = _gpu_evidence()
    profile = _profile()
    verifier = _verifier(_verifier_result(evidence, profile, devices=devices))
    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(verifier, evidence, profile)

    assert raised.value.category == "gpu_policy_denied"


def test_swapped_or_stale_gpu_challenge_is_rejected():
    evidence = _gpu_evidence()
    profile = _profile()
    result = _verifier_result(
        evidence,
        profile,
        challenge_digest="sha256:" + "0" * 64,
    )
    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(_verifier(result), evidence, profile)
    assert raised.value.category == "gpu_component_denied"


def test_topology_metadata_is_audit_only_and_never_changes_profile_admission():
    evidence = _gpu_evidence()
    profile = _profile()
    accepted = _verify_gpu(
        _verifier(
            _verifier_result(
                evidence,
                profile,
                topology_metadata={"claimed_admission": True, "links": ["fabric-x"]},
            )
        ),
        evidence,
        profile,
    )
    alternate = _verify_gpu(
        _verifier(
            _verifier_result(
                evidence,
                profile,
                topology_metadata={"claimed_admission": False, "links": []},
            )
        ),
        evidence,
        profile,
    )

    assert accepted.digest == alternate.digest
    assert accepted.topology_digest != alternate.topology_digest
    assert accepted.topology_digest is not None
    assert "claimed_admission" not in str(accepted.audit_dict())


@pytest.mark.parametrize(
    "override",
    [
        {"vendor_verified": False},
        {"host_session_verified": False},
        {"composite_binding_verified": False},
        {"tdx_component_digest": "sha256:" + "0" * 64},
        {"cpu_tee": EvidenceKind.SEV_SNP.value},
        {"tdx_measurement": "other-measurement"},
        {"tdx_platform_id": "tdx-platform-sha256:" + "0" * 64},
    ],
)
def test_gpu_requires_vendor_host_session_and_pinned_verifier(override):
    evidence = _gpu_evidence()
    profile = _profile()
    verifier = _verifier(_verifier_result(evidence, profile, **override), profile)

    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(verifier, evidence, profile)

    assert raised.value.category == "gpu_component_denied"


@pytest.mark.parametrize(
    "override",
    [
        {"schema": "cathedral_gpu_verifier_result_v0"},
        {"profile_digest": "sha256:" + "b" * 64},
        {"verifier_digest": "sha256:" + "b" * 64},
        {"vendor_verified": "true"},
        {"challenge_digest": 7},
        {"challenge_digest": "not-a-digest"},
        {"host_session_digest": 7},
        {"tdx_component_digest": "not-a-digest"},
        {"cpu_tee": 7},
        {"cpu_tee": "unknown_tee"},
        {"tdx_measurement": 7},
        {"tdx_measurement": "not a measurement"},
        {"tdx_platform_id": 7},
        {"tdx_platform_id": "not a platform"},
        {"devices": "not-a-list"},
        {"devices": [{"gpu_uuid": GPU_1}]},
        {"devices": [_device(GPU_1), _device(GPU_1)]},
        {
            "devices": [
                _device(GPU_1, evidence_verified="true"),
                _device(GPU_2),
            ]
        },
        {"topology_metadata": "not-structured-metadata"},
    ],
)
def test_gpu_verifier_protocol_and_authority_mismatch_is_infrastructure(override):
    evidence = _gpu_evidence()
    profile = _profile()
    verifier = _verifier(_verifier_result(evidence, profile, **override), profile)

    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(verifier, evidence, profile)

    assert raised.value.category == "verifier_unavailable"


def test_gpu_verifier_rechecks_input_bounds_and_configuration_is_immutable():
    evidence = _gpu_evidence()
    profile = _profile()
    verifier = _verifier(_verifier_result(evidence, profile), profile)
    oversized = Evidence(
        kind=EvidenceKind.GPU_CC,
        quote=b"q" * (2 * 1024 * 1024 + 1),
        cert_chain=[],
        nonce=NONCE,
        miner_hotkey=HOTKEY,
        report_data_version=2,
        channel_binding=_binding(),
    )

    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(verifier, oversized, profile)
    assert raised.value.category == "gpu_component_denied"

    with pytest.raises(AttributeError):
        verifier._runner = StaticRunner({}, profile=profile)


def test_gpu_verifier_rejects_mutable_or_user_owned_artifact(tmp_path: Path):
    helper = tmp_path / "gpu-verifier"
    shutil.copyfile(NATIVE_TEST_EXECUTABLE, helper)
    helper.chmod(0o755)

    with pytest.raises(GpuAttestationError) as raised:
        ExternalGpuVerifier(
            ExternalVerifierConfig(
                (str(helper),),
                implementation_artifacts=(str(helper),),
            ),
            production_mode=False,
        )

    assert raised.value.category == "verifier_config_invalid"


def test_gpu_production_verifier_rejects_non_static_executable(monkeypatch):
    monkeypatch.setattr("cathedral.gpu._is_static_tdx_elf", lambda *_args: False)

    with pytest.raises(GpuAttestationError) as raised:
        ExternalGpuVerifier(TEST_VERIFIER_CONFIG)

    assert raised.value.category == "verifier_config_invalid"


def test_static_tdx_elf_parser_rejects_loader_dependency():
    static_image = bytearray(64 + 56)
    static_image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", static_image, 16, 2, 62, 1)
    struct.pack_into("<Q", static_image, 32, 64)
    struct.pack_into("<HH", static_image, 54, 56, 1)
    struct.pack_into("<I", static_image, 64, 1)
    assert _is_static_tdx_elf(io.BytesIO(static_image), len(static_image))

    dynamic_image = bytearray(64 + 2 * 56)
    dynamic_image[:64] = static_image[:64]
    struct.pack_into("<H", dynamic_image, 56, 2)
    struct.pack_into("<I", dynamic_image, 64, 1)
    struct.pack_into("<I", dynamic_image, 120, 3)
    assert not _is_static_tdx_elf(io.BytesIO(dynamic_image), len(dynamic_image))

    linked_image = bytearray(64 + 2 * 56 + 32)
    linked_image[:64] = static_image[:64]
    struct.pack_into("<H", linked_image, 56, 2)
    struct.pack_into("<I", linked_image, 64, 1)
    struct.pack_into("<I", linked_image, 120, 2)
    struct.pack_into("<Q", linked_image, 128, 64 + 2 * 56)
    struct.pack_into("<Q", linked_image, 152, 32)
    struct.pack_into("<QQ", linked_image, 176, 1, 1)
    struct.pack_into("<QQ", linked_image, 192, 0, 0)
    assert not _is_static_tdx_elf(io.BytesIO(linked_image), len(linked_image))


@pytest.mark.parametrize(
    "command",
    [
        (
            str(Path(shutil.which("python3") or "/usr/bin/python3").resolve()),
            "-m",
            "vendor_verifier",
        ),
        (
            str(Path(shutil.which("python3") or "/usr/bin/python3").resolve()),
            "-c",
            "import vendor_verifier",
        ),
    ],
)
def test_gpu_verifier_rejects_interpreter_module_and_inline_discovery(command):
    with pytest.raises(GpuAttestationError) as module_error:
        ExternalGpuVerifier(
            ExternalVerifierConfig(
                command,
                implementation_artifacts=(command[0],),
            ),
            production_mode=False,
        )
    assert module_error.value.category == "verifier_config_invalid"


@pytest.mark.parametrize("argument", ["vendor_verifier.py", "--plugin=rules"])
def test_gpu_verifier_rejects_every_argv_extension(argument):
    with pytest.raises(GpuAttestationError) as relative_error:
        ExternalGpuVerifier(
            ExternalVerifierConfig(
                (NATIVE_TEST_EXECUTABLE, argument),
                implementation_artifacts=(NATIVE_TEST_EXECUTABLE,),
            ),
            production_mode=False,
        )
    assert relative_error.value.category == "verifier_config_invalid"


def test_gpu_component_digest_is_bound_to_raw_verified_evidence():
    profile = _profile()
    first_evidence = _gpu_evidence()
    second_evidence = Evidence(
        kind=EvidenceKind.GPU_CC,
        quote=b"different-vendor-attestation-bundle",
        cert_chain=first_evidence.cert_chain,
        nonce=first_evidence.nonce,
        miner_hotkey=first_evidence.miner_hotkey,
        composite_jwt=first_evidence.composite_jwt,
        report_data_version=2,
        channel_binding=first_evidence.channel_binding,
    )
    first = _verify_gpu(
        _verifier(_verifier_result(first_evidence, profile), profile),
        first_evidence,
        profile,
    )
    second = _verify_gpu(
        _verifier(_verifier_result(second_evidence, profile), profile),
        second_evidence,
        profile,
    )

    assert first.evidence_digest != second.evidence_digest
    assert first.digest != second.digest
    assert first.audit_dict()["evidence_digest"] != second.audit_dict()["evidence_digest"]


def test_gpu_verifier_joins_vendor_result_to_exact_verified_tdx_component():
    profile = _profile()
    gpu_evidence = _gpu_evidence()
    tdx_evidence = _tdx_evidence()
    tdx_verdict = _cpu_attested(Policy(allowed_measurements=frozenset({"cpu-measurement"})))
    result = _verifier_result(
        gpu_evidence,
        profile,
        tdx_evidence=tdx_evidence,
        tdx_verdict=tdx_verdict,
    )
    verifier = _verifier(result, profile)

    accepted = _verify_gpu(
        verifier,
        gpu_evidence,
        profile,
        tdx_evidence=tdx_evidence,
        tdx_verdict=tdx_verdict,
    )
    request = verifier._runner.requests[-1]
    expected_digest = tdx_component_binding_digest(tdx_evidence, tdx_verdict)

    assert accepted.tdx_component_digest == expected_digest
    assert request["tdx_component_digest"] == expected_digest
    assert request["tdx_quote_b64"] == base64.b64encode(tdx_evidence.quote).decode()
    assert request["tdx_measurement"] == tdx_verdict.measurement
    assert request["tdx_platform_id"] == tdx_verdict.chip_id

    swapped_tdx = replace(tdx_evidence, quote=b"different-valid-tdx-quote")
    with pytest.raises(GpuAttestationError) as raised:
        _verify_gpu(
            verifier,
            gpu_evidence,
            profile,
            tdx_evidence=swapped_tdx,
            tdx_verdict=tdx_verdict,
        )
    assert raised.value.category == "gpu_component_denied"


def test_gpu_verifier_input_cap_fits_two_maximum_evidence_envelopes():
    certificate = b"c" * MAX_EVIDENCE_CERTIFICATE_BYTES
    binding = _binding()
    gpu_evidence = Evidence(
        kind=EvidenceKind.GPU_CC,
        quote=b"g" * MAX_EVIDENCE_QUOTE_BYTES,
        cert_chain=[certificate] * MAX_EVIDENCE_CERTIFICATES,
        nonce=NONCE,
        miner_hotkey=HOTKEY,
        composite_jwt="j" * MAX_COMPOSITE_JWT_BYTES,
        report_data_version=2,
        channel_binding=binding,
    )
    tdx_evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=b"t" * MAX_EVIDENCE_QUOTE_BYTES,
        cert_chain=[certificate] * MAX_EVIDENCE_CERTIFICATES,
        nonce=NONCE,
        miner_hotkey=HOTKEY,
        report_data_version=2,
        channel_binding=binding,
    )
    tdx_verdict = _cpu_attested(
        Policy(allowed_measurements=frozenset({"cpu-measurement"})), binding
    )
    config = replace(
        TEST_VERIFIER_CONFIG,
        maximum_input_bytes=MAX_GPU_VERIFIER_INPUT_BYTES,
    )
    verifier = ExternalGpuVerifier(config, production_mode=False)
    profile = _profile(verifier_digest=verifier.implementation_digest)
    runner = StaticRunner(
        _verifier_result(
            gpu_evidence,
            profile,
            tdx_evidence=tdx_evidence,
            tdx_verdict=tdx_verdict,
        ),
        profile=profile,
    )
    object.__setattr__(verifier, "_runner", runner)

    _verify_gpu(
        verifier,
        gpu_evidence,
        profile,
        tdx_evidence=tdx_evidence,
        tdx_verdict=tdx_verdict,
    )
    payload = (
        json.dumps(
            runner.requests[-1],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )

    assert len(payload) <= config.maximum_input_bytes
    assert config.maximum_input_bytes == 32 * 1024 * 1024


def test_composite_requires_same_nonce_hotkey_channel_and_tdx(monkeypatch):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    cpu = _tdx_evidence()
    gpu = _gpu_evidence()
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))
    verifier = _verifier(_verifier_result(gpu, _profile()))
    result = verify_composite_gpu(cpu, gpu, NONCE, policy, _profile(), verifier)
    assert result.attested.tier is Tier.CC_GPU
    assert result.attested.policy_mode == gpu_profile_authority(_profile())
    assert result.attested.measurement == gpu_lifecycle_measurement("cpu-measurement", _profile())
    assert result.attested.assurance is not None
    assert result.attested.assurance.channel.status is ClaimStatus.NOT_EVALUATED

    for mismatched in (
        _gpu_evidence(nonce=b"x" * 32),
        _gpu_evidence(hotkey="other-hotkey"),
        _gpu_evidence(binding=_binding(b"z" * 32)),
    ):
        with pytest.raises(GpuAttestationError) as raised:
            verify_composite_gpu(cpu, mismatched, NONCE, policy, _profile(), verifier)
        assert raised.value.category == "composite_binding_denied"


def test_gpu_lifecycle_policy_is_stable_across_two_fresh_epochs(monkeypatch, tmp_path):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = _profile()
    cpu = _tdx_evidence()
    first_gpu = _gpu_evidence()
    second_gpu = replace(first_gpu, quote=b"fresh-vendor-gpu-attestation-bundle")
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))

    first = verify_composite_gpu(
        cpu,
        first_gpu,
        NONCE,
        policy,
        profile,
        _verifier(_verifier_result(first_gpu, profile)),
    )
    second = verify_composite_gpu(
        cpu,
        second_gpu,
        NONCE,
        policy,
        profile,
        _verifier(_verifier_result(second_gpu, profile)),
    )

    assert first.gpu_component.digest != second.gpu_component.digest
    assert first.attested.measurement == second.attested.measurement
    allowed = gpu_lifecycle_measurements(policy, profile)
    assert allowed == frozenset({first.attested.measurement})

    store = RegistryStore(str(tmp_path / "gpu-lifecycle.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    store.record_verdict(HOTKEY, first.attested)
    assert store.apply_lifecycle_policy(allowed) == ()
    assert store.apply_lifecycle_policy(allowed) == ()
    assert store.lifecycle_snapshot(HOTKEY).state is WorkerLifecycleState.ATTESTED

    changed_profile = _profile(allowed_drivers=frozenset({"551.00.00"}))
    revoked = store.apply_lifecycle_policy(gpu_lifecycle_measurements(policy, changed_profile))
    assert len(revoked) == 1
    assert revoked[0].state is WorkerLifecycleState.REVOKED


def test_gpu_bundle_never_downgrades_to_cpu_when_composite_is_unconfigured(monkeypatch):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    monkeypatch.setattr("cathedral.prober.verifier.verify", lambda *_args: _cpu_attested(policy))
    assert verify_cc_evidence_bundle([_tdx_evidence(), _gpu_evidence()], NONCE, policy) is None


def test_gpu_request_rejects_tdx_only_omission_instead_of_cpu_downgrade(monkeypatch):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    monkeypatch.setattr("cathedral.prober.verifier.verify", lambda *_args: _cpu_attested(policy))

    assert (
        verify_cc_evidence_bundle(
            [_tdx_evidence()],
            NONCE,
            policy,
            gpu_profile=_profile(),
            gpu_verifier=_verifier({}, _profile()),
            gpu_identity_registry=object(),
            expected_tier=Tier.CC_GPU,
        )
        is None
    )


def test_production_gpu_probe_enforces_runtime_startup_guards_before_work(
    tmp_path: Path, monkeypatch
):
    class EmptyStore:
        verification_ttl_seconds = 60

        def due_refreshes(self, **_kwargs):
            return ()

        def enrollments(self):
            return ()

    store = EmptyStore()
    database, anchor = _production_identity_paths(tmp_path)
    registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )

    with pytest.raises(ValueError, match="profile or identity registry"):
        probe_once(
            store,
            Policy(),
            production_mode=True,
            gpu_profile=object(),
            gpu_verifier=object(),
            gpu_identity_registry=object(),
            expected_tier=Tier.CC_GPU,
        )

    signed_profile = _profile(
        registry_release=1,
        registry_digest="sha256:" + "7" * 64,
    )
    object.__setattr__(signed_profile, "registry_valid_from", NOW - timedelta(days=1))
    object.__setattr__(signed_profile, "registry_valid_until", NOW + timedelta(days=1))
    object.__setattr__(signed_profile, "_registry_verified", True)
    signed_policy = Policy(
        registry_release=1,
        registry_digest="sha256:" + "7" * 64,
    )
    development_verifier = ExternalGpuVerifier(
        TEST_VERIFIER_CONFIG,
        production_mode=False,
    )
    with pytest.raises(ValueError, match="static verifier executable"):
        probe_once(
            store,
            signed_policy,
            production_mode=True,
            gpu_profile=signed_profile,
            gpu_verifier=development_verifier,
            gpu_identity_registry=registry,
            expected_tier=Tier.CC_GPU,
        )

    production_verifier = object.__new__(ExternalGpuVerifier)
    object.__setattr__(production_verifier, "_production_ready", True)
    preflights = []
    monkeypatch.setattr(
        ExternalGpuVerifier,
        "preflight",
        lambda self, profile: preflights.append((self, profile)),
    )

    probe_once(
        store,
        signed_policy,
        production_mode=True,
        gpu_profile=signed_profile,
        gpu_verifier=production_verifier,
        gpu_identity_registry=registry,
        expected_tier=Tier.CC_GPU,
    )

    assert preflights == [(production_verifier, signed_profile)]


def test_gpu_probe_rolls_back_claim_when_endpoint_generation_changes(tmp_path: Path, monkeypatch):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = _profile()
    cpu_evidence = _tdx_evidence()
    gpu_evidence = _gpu_evidence()
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))
    composite = verify_composite_gpu(
        cpu_evidence,
        gpu_evidence,
        NONCE,
        policy,
        profile,
        _verifier(_verifier_result(gpu_evidence, profile), profile),
    )
    monkeypatch.setattr("cathedral.gpu.verify_composite_gpu", lambda *_args: composite)

    store = RegistryStore(str(tmp_path / "probe-registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    original = store.lifecycle_snapshot(HOTKEY)
    identity_registry = GpuIdentityRegistry(
        tmp_path / "probe-gpu-identities.sqlite",
        identity_digest_key=b"i" * 32,
    )
    claim_events = []
    begin_claim = identity_registry.begin_claim
    rollback_claim = identity_registry.rollback_claim
    commit_claim = identity_registry.commit_claim

    def tracked_begin(*args, **kwargs):
        claim_events.append("begin")
        return begin_claim(*args, **kwargs)

    def tracked_rollback(pending):
        claim_events.append("rollback")
        return rollback_claim(pending)

    def tracked_commit(pending):
        claim_events.append("commit")
        return commit_claim(pending)

    monkeypatch.setattr(identity_registry, "begin_claim", tracked_begin)
    monkeypatch.setattr(identity_registry, "rollback_claim", tracked_rollback)
    monkeypatch.setattr(identity_registry, "commit_claim", tracked_commit)

    def replace_endpoint(_endpoint, hotkey, nonce, **_kwargs):
        assert hotkey == HOTKEY
        store.enroll(HOTKEY, "http://127.0.0.1:2")
        return [
            replace(cpu_evidence, nonce=nonce),
            replace(gpu_evidence, nonce=nonce),
        ]

    monkeypatch.setattr("cathedral.prober._request_evidence", replace_endpoint)
    probe_once(
        store,
        policy,
        gpu_profile=profile,
        gpu_verifier=object(),
        gpu_identity_registry=identity_registry,
        expected_tier=Tier.CC_GPU,
    )

    current = store.lifecycle_snapshot(HOTKEY)
    assert current.generation == original.generation + 1
    assert current.revision == 1
    assert current.state is WorkerLifecycleState.PENDING
    assert store.enrollments()[0].endpoint_url == "http://127.0.0.1:2"
    assert store.board()["miners"][0]["verification_status"] == "PENDING"
    assert claim_events == ["begin", "rollback"]
    identity_registry.assert_unclaimed(composite.gpu_component)


def test_gpu_prober_revokes_cross_worker_identity_reuse(tmp_path: Path, monkeypatch):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = _profile()
    cpu_evidence = _tdx_evidence()
    gpu_evidence = _gpu_evidence()
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))
    composite = verify_composite_gpu(
        cpu_evidence,
        gpu_evidence,
        NONCE,
        policy,
        profile,
        _verifier(_verifier_result(gpu_evidence, profile), profile),
    )
    monkeypatch.setattr("cathedral.gpu.verify_composite_gpu", lambda *_args: composite)
    monkeypatch.setattr(
        "cathedral.prober._request_evidence",
        lambda *_args, **_kwargs: [cpu_evidence, gpu_evidence],
    )

    identity_registry = GpuIdentityRegistry(
        tmp_path / "identity-conflict.sqlite", identity_digest_key=b"i" * 32
    )
    identity_registry.claim("existing-owner", composite.gpu_component, at=NOW)
    store = RegistryStore(str(tmp_path / "probe-registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")

    assert not probe_once(
        store,
        policy,
        gpu_profile=profile,
        gpu_verifier=object(),
        gpu_identity_registry=identity_registry,
        expected_tier=Tier.CC_GPU,
    )
    lifecycle = store.lifecycle_snapshot(HOTKEY, materialize_freshness=False)
    assert lifecycle.state is WorkerLifecycleState.REVOKED
    assert lifecycle.reason is LifecycleReason.IDENTITY_CONFLICT
    assert lifecycle.retry_count == 0


@pytest.mark.parametrize(
    "verifier_override",
    [
        {"schema": "cathedral_gpu_verifier_result_v0"},
        {"challenge_digest": 7},
        {"devices": [_device(GPU_1), _device(GPU_1)]},
        {
            "devices": [
                _device(GPU_1, evidence_verified="true"),
                _device(GPU_2),
            ]
        },
        {"topology_metadata": "not-structured-metadata"},
    ],
)
def test_gpu_prober_retries_post_preflight_protocol_mismatch(
    tmp_path: Path, monkeypatch, verifier_override
):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = _profile()
    cpu_evidence = _tdx_evidence()
    gpu_evidence = _gpu_evidence()
    verifier = _verifier(
        _verifier_result(
            gpu_evidence,
            profile,
            **verifier_override,
        ),
        profile,
    )
    monkeypatch.setattr("cathedral.prober.issue_nonce", lambda: NONCE)
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))
    monkeypatch.setattr(
        "cathedral.prober._request_evidence",
        lambda *_args, **_kwargs: [cpu_evidence, gpu_evidence],
    )
    store = RegistryStore(str(tmp_path / "protocol-registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    identity_registry = GpuIdentityRegistry(
        tmp_path / "protocol-identities.sqlite", identity_digest_key=b"i" * 32
    )

    assert not probe_once(
        store,
        policy,
        gpu_profile=profile,
        gpu_verifier=verifier,
        gpu_identity_registry=identity_registry,
        expected_tier=Tier.CC_GPU,
    )
    lifecycle = store.lifecycle_snapshot(HOTKEY, materialize_freshness=False)
    assert lifecycle.state is WorkerLifecycleState.PENDING
    assert lifecycle.retry_count == 1
    assert lifecycle.next_retry_at is not None


@pytest.mark.parametrize(
    "verifier_override",
    [
        {"cpu_tee": EvidenceKind.SEV_SNP.value},
        {"tdx_measurement": "other-measurement"},
        {"tdx_platform_id": "tdx-platform-sha256:" + "0" * 64},
    ],
)
def test_gpu_prober_terminally_rejects_canonical_cpu_binding_mismatch(
    tmp_path: Path, monkeypatch, verifier_override
):
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = _profile()
    cpu_evidence = _tdx_evidence()
    gpu_evidence = _gpu_evidence()
    verifier = _verifier(
        _verifier_result(gpu_evidence, profile, **verifier_override),
        profile,
    )
    monkeypatch.setattr("cathedral.prober.issue_nonce", lambda: NONCE)
    monkeypatch.setattr("cathedral.verify.verify", lambda *_args: _cpu_attested(policy))
    monkeypatch.setattr(
        "cathedral.prober._request_evidence",
        lambda *_args, **_kwargs: [cpu_evidence, gpu_evidence],
    )
    store = RegistryStore(str(tmp_path / "binding-registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    identity_registry = GpuIdentityRegistry(
        tmp_path / "binding-identities.sqlite", identity_digest_key=b"i" * 32
    )

    assert not probe_once(
        store,
        policy,
        gpu_profile=profile,
        gpu_verifier=verifier,
        gpu_identity_registry=identity_registry,
        expected_tier=Tier.CC_GPU,
    )
    lifecycle = store.lifecycle_snapshot(HOTKEY, materialize_freshness=False)
    assert lifecycle.state is WorkerLifecycleState.FAILED
    assert lifecycle.retry_count == 0
    assert lifecycle.next_retry_at is None


def test_maximum_gpu_bundle_fits_validator_working_set_reservation():
    quote = b"q" * MAX_EVIDENCE_QUOTE_BYTES
    certificate = b"c" * MAX_EVIDENCE_CERTIFICATE_BYTES
    encoded_quote = base64.b64encode(quote).decode("ascii")
    encoded_certificate = base64.b64encode(certificate).decode("ascii")
    request = {
        "cert_chain_b64": [encoded_certificate] * MAX_EVIDENCE_CERTIFICATES,
        "composite_jwt": "j" * MAX_COMPOSITE_JWT_BYTES,
        "quote_b64": encoded_quote,
        "tdx_cert_chain_b64": [encoded_certificate] * MAX_EVIDENCE_CERTIFICATES,
        "tdx_quote_b64": encoded_quote,
    }
    encoded_request = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    verifier_peak = MAX_GPU_EVIDENCE_DECODED_BYTES + 3 * len(encoded_request)
    decode_peak = 2 * MAX_EVIDENCE_RESPONSE_BODY + MAX_GPU_EVIDENCE_DECODED_BYTES

    assert len(encoded_request) <= MAX_GPU_VERIFIER_REQUEST_BYTES
    assert max(verifier_peak, decode_peak) <= MAX_GPU_EVIDENCE_WORKING_SET_BYTES
    assert MAX_GPU_EVIDENCE_RESERVATION_BYTES <= MAX_GPU_EVIDENCE_IN_FLIGHT_BYTES
    assert MAX_GPU_EVIDENCE_CONCURRENCY == 1
    assert MAX_EVIDENCE_COMPONENTS == 2
    assert MAX_EVIDENCE_COMPONENT_JSON_OVERHEAD >= 64 * 1024


def test_gpu_runtime_enforces_process_wide_evidence_lifetime_budget(tmp_path: Path, monkeypatch):
    collection_active = 0
    maximum_collection_active = 0
    verification_active = 0
    maximum_verification_active = 0
    guard = threading.Lock()
    configured_limits = []

    class BudgetClient:
        def __init__(self, hotkey):
            self.hotkey = hotkey

        def collect_evidence_bundle(self, nonce):
            nonlocal collection_active, maximum_collection_active
            with guard:
                collection_active += 1
                maximum_collection_active = max(maximum_collection_active, collection_active)
            try:
                time.sleep(0.02)
                return (
                    Evidence(EvidenceKind.TDX, b"tdx", nonce, self.hotkey),
                    Evidence(EvidenceKind.GPU_CC, b"gpu", nonce, self.hotkey),
                )
            finally:
                with guard:
                    collection_active -= 1

    def factory(_endpoint, hotkey, **kwargs):
        configured_limits.append(kwargs["max_response_body"])
        return BudgetClient(hotkey)

    def bounded_verification(*_args, **_kwargs):
        nonlocal verification_active, maximum_verification_active
        with guard:
            verification_active += 1
            maximum_verification_active = max(maximum_verification_active, verification_active)
        try:
            time.sleep(0.02)
            raise GpuAttestationError(
                "verifier_unavailable", "bounded synthetic verification failure"
            )
        finally:
            with guard:
                verification_active -= 1

    monkeypatch.setattr("cathedral.gpu.verify_composite_gpu", bounded_verification)

    ledger = Ledger(tmp_path / "budget-ledger.sqlite")
    runtime = ConfidentialRuntime(
        RegistryStore(str(tmp_path / "budget-registry.sqlite")),
        ledger,
        Policy(allowed_measurements=frozenset({"cpu-measurement"})),
        remote_factory=factory,
        config=RuntimeConfig(
            max_workers=64,
            production_mode=False,
            allow_insecure_http_for_tests=True,
            expected_tier=Tier.CC_GPU,
        ),
        gpu_profile=_profile(),
        gpu_verifier=object(),
        gpu_identity_registry=GpuIdentityRegistry(
            tmp_path / "budget-identities.sqlite", identity_digest_key=b"i" * 32
        ),
    )
    targets = [
        MinerTarget(f"worker-{index}", f"http://127.0.0.1:{9000 + index}") for index in range(8)
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(runtime.audit_attestation, targets))

    assert all(outcome.status == "attestation_failed" for outcome in outcomes)
    assert configured_limits == [MAX_EVIDENCE_RESPONSE_BODY] * len(targets)
    assert MAX_GPU_EVIDENCE_CONCURRENCY == 1
    assert maximum_collection_active == MAX_GPU_EVIDENCE_CONCURRENCY
    assert maximum_verification_active == MAX_GPU_EVIDENCE_CONCURRENCY
    runtime.close()
    ledger.close()


def test_gpu_identity_registry_prevents_one_device_set_backing_two_workers(tmp_path: Path):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    component = _component()

    def claim(hotkey):
        try:
            registry.claim(hotkey, component, at=NOW)
            return "accepted"
        except GpuAttestationError as exc:
            return exc.category

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, ["worker-a", "worker-b"]))

    assert sorted(outcomes) == ["accepted", "identity_conflict"]
    winner = "worker-a" if outcomes[0] == "accepted" else "worker-b"
    registry.claim(winner, component, at=NOW)

    database_bytes = database.read_bytes()
    assert GPU_1.encode() not in database_bytes
    assert winner.encode() not in database_bytes


def test_gpu_identity_registry_allows_fresh_bundle_for_same_worker(tmp_path: Path):
    registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    first = _component()
    second_evidence = _gpu_evidence(nonce=b"f" * 32)
    second = _component(second_evidence, _profile())

    registry.claim("worker-a", first, at=NOW)
    registry.claim("worker-a", second, at=NOW)


def test_gpu_canary_reservation_is_exclusive_and_released(tmp_path: Path):
    registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    component = _component()

    reservation = registry.begin_exclusive_reservation("canary", component, at=NOW)
    with pytest.raises(GpuAttestationError) as reserved:
        registry.claim("worker", component, at=NOW)
    assert reserved.value.category == "identity_conflict"

    registry.rollback_claim(reservation)
    registry.claim("worker", component, at=NOW)
    with pytest.raises(GpuAttestationError) as enrolled:
        registry.assert_unclaimed(component)
    assert enrolled.value.category == "identity_conflict"


def test_gpu_identity_pending_claim_rolls_back_rejected_admission(tmp_path: Path):
    registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    component = _component()

    pending = registry.begin_claim("rejected-worker", component, at=NOW)
    registry.rollback_claim(pending)
    registry.claim("accepted-worker", component, at=NOW)


def test_same_worker_pending_gpu_claim_requires_recovery_without_identity_conflict(
    tmp_path: Path,
):
    registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    component = _component()
    pending = registry.begin_claim("worker-a", component, at=NOW)

    with pytest.raises(GpuAttestationError) as busy:
        registry.begin_claim("worker-a", component, at=NOW)

    assert busy.value.category == "identity_recovery_required"
    registry.rollback_claim(pending)
    registry.claim("worker-a", component, at=NOW)


def test_gpu_identity_interrupted_worker_claim_requires_authenticated_recovery(
    tmp_path: Path,
):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    component = _component()
    pending = registry.begin_claim("worker-a", component, at=NOW)

    with pytest.raises(GpuAttestationError) as raised:
        GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    assert raised.value.category == "identity_recovery_required"

    with pytest.raises(GpuAttestationError) as wrong_key:
        GpuIdentityRegistry.recover_interrupted(
            database,
            identity_digest_key=b"j" * 32,
            reason="validator terminated during worker admission",
        )
    assert wrong_key.value.category == "identity_config_invalid"

    outcome = GpuIdentityRegistry.recover_interrupted(
        database,
        identity_digest_key=b"i" * 32,
        reason="validator terminated during worker admission",
    )
    assert outcome["worker_claims_committed"] == 1
    assert outcome["worker_identities_committed"] == 2
    assert outcome["canary_reservations_released"] == 0
    assert len(outcome["claim_token_digests"]) == 1

    recovered = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    assert dict(recovered.recovery_history()[0]) == dict(outcome)
    recovered.claim("worker-a", component, at=NOW)
    with pytest.raises(GpuAttestationError) as conflict:
        recovered.claim("worker-b", component, at=NOW)
    assert conflict.value.category == "identity_conflict"
    assert pending.token.encode() not in database.read_bytes()

    with pytest.raises(GpuAttestationError) as no_recovery:
        GpuIdentityRegistry.recover_interrupted(
            database,
            identity_digest_key=b"i" * 32,
            reason="duplicate recovery attempt",
        )
    assert no_recovery.value.category == "identity_recovery_not_required"


def test_gpu_identity_recovery_releases_only_interrupted_canary(tmp_path: Path):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    component = _component()
    registry.begin_exclusive_reservation("canary", component, at=NOW)

    outcome = GpuIdentityRegistry.recover_interrupted(
        database,
        identity_digest_key=b"i" * 32,
        reason="validator terminated during canary epoch",
    )

    assert outcome["worker_claims_committed"] == 0
    assert outcome["canary_reservations_released"] == 1
    assert outcome["canary_identities_released"] == 2
    recovered = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    recovered.claim("worker-a", component, at=NOW)


def test_gpu_identity_registry_rejects_identity_key_rotation(tmp_path: Path):
    database = tmp_path / "gpu-identities.sqlite"
    GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)

    with pytest.raises(GpuAttestationError) as raised:
        GpuIdentityRegistry(database, identity_digest_key=b"j" * 32)

    assert raised.value.category == "identity_config_invalid"


def test_production_gpu_identity_registry_rejects_unsafe_permissions(tmp_path: Path):
    tmp_path.chmod(0o700)
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o755)
    unsafe_parent.chmod(0o755)
    anchor_parent = tmp_path / "safe-anchor"
    anchor_parent.mkdir(mode=0o700)
    anchor_parent.chmod(0o700)

    with pytest.raises(GpuAttestationError) as parent_error:
        GpuIdentityRegistry(
            unsafe_parent / "gpu-identities.sqlite",
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor_parent / "generation.anchor",
            initialize=True,
        )
    assert parent_error.value.category == "identity_config_invalid"

    database, anchor = _production_identity_paths(tmp_path / "file-permissions")
    GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )
    database.chmod(0o644)
    with pytest.raises(GpuAttestationError) as file_error:
        GpuIdentityRegistry(
            database,
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor,
        )
    assert file_error.value.category == "identity_config_invalid"


def test_production_gpu_identity_registry_rejects_path_replacement(tmp_path: Path):
    tmp_path.chmod(0o700)
    database, anchor = _production_identity_paths(tmp_path)
    registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )
    backup = tmp_path / "gpu-identities.original.sqlite"
    database.rename(backup)
    database.touch(mode=0o600)

    with pytest.raises(GpuAttestationError) as raised:
        registry.assert_unclaimed(_component())
    assert raised.value.category == "identity_config_invalid"


def test_production_gpu_identity_registry_requires_explicit_initialization(
    tmp_path: Path,
):
    database, anchor = _production_identity_paths(tmp_path)

    with pytest.raises(GpuAttestationError) as missing:
        GpuIdentityRegistry(
            database,
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor,
        )
    assert missing.value.category == "identity_config_invalid"

    registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )
    registry.claim("worker-a", _component(), at=NOW)
    database.unlink()

    with pytest.raises(GpuAttestationError) as deleted:
        GpuIdentityRegistry(
            database,
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor,
        )
    assert deleted.value.category == "identity_config_invalid"

    with pytest.raises(GpuAttestationError) as reset:
        GpuIdentityRegistry(
            database,
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor,
            initialize=True,
        )
    assert reset.value.category == "identity_config_invalid"


def test_gpu_identity_generation_lock_covers_database_commit(tmp_path: Path, monkeypatch):
    registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    anchor_written = threading.Event()
    allow_commit = threading.Event()
    original_append = registry._append_generation_anchor

    def paused_append(previous, generation):
        original_append(previous, generation)
        anchor_written.set()
        assert allow_commit.wait(timeout=5)

    monkeypatch.setattr(registry, "_append_generation_anchor", paused_append)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(registry.begin_claim, "worker-a", _component())
        assert anchor_written.wait(timeout=5)
        second = executor.submit(registry.begin_claim, "worker-b", _component())
        assert not second.done()
        allow_commit.set()
        pending = first.result(timeout=5)
        with pytest.raises(GpuAttestationError) as conflict:
            second.result(timeout=5)

    assert conflict.value.category == "identity_conflict"
    registry.rollback_claim(pending)


def test_gpu_identity_registry_recovers_database_commit_before_anchor_update(
    tmp_path: Path, monkeypatch
):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    original_append = registry._append_generation_anchor

    def interrupted_anchor_update(_previous, _generation):
        raise GpuAttestationError(
            "identity_config_invalid", "simulated process death before anchor update"
        )

    monkeypatch.setattr(registry, "_append_generation_anchor", interrupted_anchor_update)
    with pytest.raises(GpuAttestationError) as interrupted:
        registry.begin_claim("worker-a", _component(), at=NOW)
    assert interrupted.value.category == "identity_config_invalid"
    monkeypatch.setattr(registry, "_append_generation_anchor", original_append)

    with pytest.raises(GpuAttestationError) as recovery_required:
        GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    assert recovery_required.value.category == "identity_recovery_required"
    outcome = GpuIdentityRegistry.recover_interrupted(
        database,
        identity_digest_key=b"i" * 32,
        reason="validator terminated after the identity database commit",
    )
    assert outcome["worker_claims_committed"] == 1
    assert GpuIdentityRegistry(database, identity_digest_key=b"i" * 32).recovery_history()


def test_gpu_identity_anchor_retains_previous_slot_during_interrupted_write(
    tmp_path: Path,
):
    database = tmp_path / "gpu-identities.sqlite"
    anchor = Path(f"{database}.generation")
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    registry.claim("worker-a", _component(), at=NOW)
    assert registry._read_generation_anchor() == 2

    with anchor.open("r+b") as handle:
        handle.seek(0)
        handle.write(b"interrupted-anchor-write")
        handle.flush()

    assert registry._read_generation_anchor() == 1
    registry.claim("worker-a", _component(), at=NOW)
    assert registry._read_generation_anchor() == 4


def test_gpu_identity_registry_detects_claim_and_mac_anchor_deletion(tmp_path: Path):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    registry.claim("worker-a", _component(), at=NOW)

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM gpu_identity_claims_v3")
        connection.execute("DELETE FROM gpu_identity_registry_meta_v1")

    with pytest.raises(GpuAttestationError) as raised:
        registry.assert_unclaimed(_component())
    assert raised.value.category == "identity_config_invalid"
    with pytest.raises(GpuAttestationError) as reopened:
        GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    assert reopened.value.category == "identity_config_invalid"


def test_gpu_identity_registry_rejects_mutating_trigger_before_claim_commit(
    tmp_path: Path,
):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    pending = registry.begin_claim("worker-a", _component(), at=NOW)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TRIGGER erase_gpu_claims AFTER UPDATE ON gpu_identity_claims_v3 "
            "BEGIN DELETE FROM gpu_identity_claims_v3; END"
        )

    with pytest.raises(GpuAttestationError) as raised:
        registry.commit_claim(pending)
    assert raised.value.category == "identity_config_invalid"


def test_gpu_identity_registry_external_generation_rejects_database_rollback(
    tmp_path: Path,
):
    database, anchor = _production_identity_paths(tmp_path)
    snapshot = tmp_path / "gpu-identities.snapshot.sqlite"
    registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )
    shutil.copyfile(database, snapshot)
    registry.claim("worker-a", _component(), at=NOW)

    shutil.copyfile(snapshot, database)

    with pytest.raises(GpuAttestationError) as raised:
        registry.assert_unclaimed(_component())
    assert raised.value.category == "identity_config_invalid"
    with pytest.raises(GpuAttestationError) as reopened:
        GpuIdentityRegistry(
            database,
            identity_digest_key=b"i" * 32,
            production_mode=True,
            generation_anchor_path=anchor,
        )
    assert reopened.value.category == "identity_config_invalid"


def test_gpu_identity_registry_authenticates_recovery_history(tmp_path: Path):
    database = tmp_path / "gpu-identities.sqlite"
    registry = GpuIdentityRegistry(database, identity_digest_key=b"i" * 32)
    registry.begin_claim("worker-a", _component(), at=NOW)
    GpuIdentityRegistry.recover_interrupted(
        database,
        identity_digest_key=b"i" * 32,
        reason="validator terminated during worker admission",
    )

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE gpu_identity_recovery_events_v1 SET reason='forged history'")

    with pytest.raises(GpuAttestationError) as raised:
        registry.recovery_history()
    assert raised.value.category == "identity_config_invalid"


def test_gpu_profile_expiry_is_checked_inside_lifecycle_commit(tmp_path: Path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    policy = Policy(
        allowed_measurements=frozenset({"cpu-measurement"}),
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    attested = replace(
        _cpu_attested(policy),
        tier=Tier.CC_GPU,
        policy_mode=gpu_profile_authority(_profile()),
    )

    with pytest.raises(LifecycleError, match="not active at lifecycle commit"):
        store.record_verdict(
            HOTKEY,
            attested,
            policy_registry_release=policy.registry_release,
            policy_registry_digest=policy.registry_digest,
            gpu_profile_valid_from=NOW - timedelta(days=1),
            gpu_profile_valid_until=NOW,
            gpu_profile_registry_release=policy.registry_release,
            gpu_profile_registry_digest=policy.registry_digest,
        )

    assert store.lifecycle_snapshot(HOTKEY).state is WorkerLifecycleState.PENDING


def test_gpu_prober_retries_verifier_infrastructure_failure_without_terminal_state(
    tmp_path: Path, monkeypatch
):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    store.enroll(HOTKEY, "http://127.0.0.1:1")
    identity_registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))

    monkeypatch.setattr(
        "cathedral.prober._request_evidence",
        lambda *_args, **_kwargs: [_tdx_evidence(), _gpu_evidence()],
    )

    def verifier_unavailable(*_args, **_kwargs):
        raise GpuAttestationError("verifier_unavailable", "GPU verifier did not return a verdict")

    monkeypatch.setattr("cathedral.gpu.verify_composite_gpu", verifier_unavailable)

    assert not probe_once(
        store,
        policy,
        production_mode=False,
        gpu_profile=_profile(),
        gpu_verifier=object(),
        gpu_identity_registry=identity_registry,
        expected_tier=Tier.CC_GPU,
    )
    lifecycle = store.lifecycle_snapshot(HOTKEY, materialize_freshness=False)
    assert lifecycle.state is WorkerLifecycleState.PENDING
    assert lifecycle.retry_count == 1
    assert lifecycle.next_retry_at is not None


def test_gpu_score_gate_requires_explicit_flag_and_active_profile(monkeypatch):
    profile = _profile()
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    authority = gpu_profile_authority(profile)
    attested = Attested(
        Tier.CC_GPU,
        "gpu-set-sha256:" + "1" * 64,
        gpu_lifecycle_measurement("cpu-measurement", profile),
        1,
        policy_mode=authority,
    )
    lane = SatLane(
        namespace="gpu-gate",
        gpu_profile=profile,
        gpu_policy=policy,
    )

    monkeypatch.delenv("CATHEDRAL_ENABLE_GPU_SCORING", raising=False)
    monkeypatch.delenv("CATHEDRAL_ACTIVE_GPU_PROFILES", raising=False)
    monkeypatch.delenv("CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES", raising=False)
    assert not gpu_score_eligible(attested, profile=profile, policy=policy)
    assert not lane.qualify(attested)

    monkeypatch.setenv("CATHEDRAL_ENABLE_GPU_SCORING", "true")
    monkeypatch.setenv("CATHEDRAL_ACTIVE_GPU_PROFILES", profile.profile_id)
    assert not lane.qualify(attested)

    changed = _profile(allowed_drivers=frozenset({"551.00.00"}))
    monkeypatch.setenv("CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES", gpu_profile_authority(changed))
    assert not lane.qualify(attested)

    monkeypatch.setenv("CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES", authority)
    assert gpu_score_eligible(attested, profile=profile, policy=policy)
    assert lane.qualify(attested)

    signed = _profile(
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    later_release = _profile(
        registry_release=8,
        registry_digest="sha256:" + "8" * 64,
    )
    assert "@release=7@registry=sha256:" in gpu_profile_authority(signed)
    assert gpu_profile_authority(signed) != gpu_profile_authority(later_release)

    object.__setattr__(signed, "_registry_verified", True)
    object.__setattr__(signed, "registry_valid_from", NOW - timedelta(days=1))
    object.__setattr__(signed, "registry_valid_until", NOW + timedelta(days=1))
    signed_policy = Policy(
        allowed_measurements=frozenset({"cpu-measurement"}),
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    signed_attested = replace(
        attested,
        measurement=gpu_lifecycle_measurement("cpu-measurement", signed),
        policy_mode=gpu_profile_authority(signed),
    )
    monkeypatch.setenv(
        "CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES",
        gpu_profile_authority(signed),
    )
    assert gpu_score_eligible(
        signed_attested,
        profile=signed,
        policy=signed_policy,
        at=NOW,
    )
    assert not gpu_score_eligible(
        signed_attested,
        profile=signed,
        policy=signed_policy,
        at=NOW + timedelta(days=2),
    )


@pytest.mark.parametrize(
    "mode", ["timeout", "oversized_output", "malformed_output", "nonzero_exit"]
)
def test_gpu_external_verifier_failures_are_bounded_and_secret_safe(mode):
    class FailingRunner:
        def _invoke(self, _request):
            raise SignatureVerifierError(mode, "bounded verifier failure")

    verifier = ExternalGpuVerifier(TEST_VERIFIER_CONFIG, production_mode=False)
    object.__setattr__(verifier, "_runner", FailingRunner())
    profile = _profile(verifier_digest=verifier.implementation_digest)

    with pytest.raises(GpuAttestationError) as raised:
        verifier.preflight(profile)

    assert raised.value.category == "verifier_unavailable"
    assert mode not in str(raised.value)


def test_gpu_preflight_requires_exact_profile_digest_and_ready_boolean():
    profile = _profile()
    verifier = ExternalGpuVerifier(TEST_VERIFIER_CONFIG, production_mode=False)
    object.__setattr__(
        verifier,
        "_runner",
        StaticRunner(
            {
                "schema": GPU_PREFLIGHT_SCHEMA,
                "profile_digest": profile.digest,
                "verifier_digest": profile.verifier_digest,
                "ready": True,
            }
        ),
    )
    verifier.preflight(profile)

    invalid = ExternalGpuVerifier(TEST_VERIFIER_CONFIG, production_mode=False)
    object.__setattr__(
        invalid,
        "_runner",
        StaticRunner(
            {
                "schema": GPU_PREFLIGHT_SCHEMA,
                "profile_digest": profile.digest,
                "verifier_digest": profile.verifier_digest,
                "ready": "true",
            }
        ),
    )
    with pytest.raises(GpuAttestationError):
        invalid.preflight(profile)
