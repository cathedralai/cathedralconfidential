"""Typed, fail-closed NVIDIA Confidential Containers / Trustee adapter tests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.cc_gpu import CcGpuJobContext
from cathedral.common import ChannelBinding, ChannelBindingType, Evidence, EvidenceKind
from cathedral.trustee import (
    TRUSTEE_BACKEND,
    TRUSTEE_PREFLIGHT_SCHEMA,
    TRUSTEE_PRODUCTION_BLOCKER,
    TRUSTEE_RESULT_SCHEMA,
    TRUSTEE_RUNTIME_MANIFEST_SCHEMA,
    TrusteeAdapterError,
    TrusteeCompositeAdapter,
    sign_trustee_runtime_manifest,
    verify_trustee_runtime_manifest,
)
from cathedral.policy_registry import canonical_json
from cathedral.workload import ExternalVerifierConfig


PROFILE = "gcp-a3-high-h100-tdx-v1"
AUTHORITY = (
    f"gpu-profile:{PROFILE}@profile=sha256:"
    + "1" * 64
    + "@release=1@registry=sha256:"
    + "2" * 64
)
POLICY = "sha256:" + "3" * 64
ARTIFACTS = "sha256:" + "4" * 64
VERIFIER = "sha256:" + "e" * 64
NONCE = b"n" * 32
BINDING = ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, b"k" * 32)


def _context() -> CcGpuJobContext:
    return CcGpuJobContext(
        worker_id="11111111-1111-4111-8111-111111111111",
        subject_hotkey="worker-hotkey",
        job_id="22222222-2222-4222-8222-222222222222",
        attempt_id="33333333-3333-4333-8333-333333333333",
        profile_id=PROFILE,
        provider="gcp",
        machine_type="a3-highgpu-1g",
        zone="us-central1-a",
        cpu_tee="intel_tdx",
        gpu_model="nvidia_h100_80gb",
        gpu_count=1,
        provisioning_model="spot",
        profile_authority=AUTHORITY,
        image_digest="sha256:" + "5" * 64,
        policy_digest="sha256:" + "6" * 64,
        input_digest="sha256:" + "7" * 64,
        model_digest="sha256:" + "8" * 64,
    )


def _evidence(kind: EvidenceKind) -> Evidence:
    return Evidence(
        kind=kind,
        quote=b"quote-" + kind.value.encode(),
        nonce=NONCE,
        miner_hotkey="worker-hotkey",
        cert_chain=[b"cert"],
        report_data_version=2,
        channel_binding=BINDING,
    )


class Runner:
    def __init__(
        self,
        *,
        mismatch: str | None = None,
        artifact_manifest_digest: str = ARTIFACTS,
        verifier_digest: str = VERIFIER,
    ) -> None:
        self.mismatch = mismatch
        self.artifact_manifest_digest = artifact_manifest_digest
        self.verifier_digest = verifier_digest
        self.requests = []

    def _invoke(self, request):
        self.requests.append(request)
        if request["operation"] == "preflight":
            return {
                "artifact_manifest_digest": self.artifact_manifest_digest,
                "backend": TRUSTEE_BACKEND,
                "profile_authority": AUTHORITY,
                "profile_id": PROFILE,
                "protocol_version": 1,
                "schema": TRUSTEE_PREFLIGHT_SCHEMA,
                "status": "ready",
                "trustee_policy_digest": POLICY,
            }
        result = {
            "backend": TRUSTEE_BACKEND,
            "channel_binding_digest": request["channel_binding_digest"],
            "composite_bundle_digest": "sha256:" + "9" * 64,
            "cpu_evidence_digest": "sha256:" + "a" * 64,
            "cpu_tee": "tdx",
            "evidence_fresh": True,
            "gpu_evidence_digest": "sha256:" + "b" * 64,
            "gpu_identity_set_digest": "sha256:" + "c" * 64,
            "gpu_cc_mode_verified": True,
            "gpu_ready_state_verified": True,
            "gpu_tee": "nvidia_cc",
            "job_context_digest": request["job_context_digest"],
            "measurement_policy_verified": True,
            "nonce_digest": "sha256:" + hashlib.sha256(NONCE).hexdigest(),
            "profile_authority": AUTHORITY,
            "profile_id": PROFILE,
            "runtime_manifest_digest": self.artifact_manifest_digest,
            "runtime_isolation_verified": True,
            "same_guest_verified": True,
            "schema": TRUSTEE_RESULT_SCHEMA,
            "secret_release_authorized": True,
            "subject_hotkey": "worker-hotkey",
            "trustee_policy_digest": POLICY,
            "verifier_digest": self.verifier_digest,
            "verdict": "verified",
        }
        if self.mismatch is not None:
            result[self.mismatch] = "sha256:" + "d" * 64
        return result


def _adapter(
    runner: Runner,
    *,
    artifact_manifest_digest: str = ARTIFACTS,
    runtime_manifest=None,
    command: str = "/usr/bin/false",
) -> TrusteeCompositeAdapter:
    return TrusteeCompositeAdapter(
        ExternalVerifierConfig((command,)),
        profile_id=PROFILE,
        profile_authority=AUTHORITY,
        trustee_policy_digest=POLICY,
        artifact_manifest_digest=artifact_manifest_digest,
        runtime_manifest=runtime_manifest,
        runner=runner,
    )


def test_trustee_adapter_invokes_exact_contract_but_is_not_launch_eligible() -> None:
    runner = Runner()
    adapter = _adapter(runner)
    adapter.preflight()
    verdict = adapter.verify(
        context=_context(),
        nonce=NONCE,
        channel_binding=BINDING,
        tdx_evidence=_evidence(EvidenceKind.TDX),
        gpu_evidence=_evidence(EvidenceKind.GPU_CC),
    )
    assert verdict.secret_release_authorized is True
    assert verdict.evidence_fresh is True
    assert verdict.launch_eligible is False
    assert adapter.production_ready is False
    assert adapter.production_blocker == TRUSTEE_PRODUCTION_BLOCKER
    request = runner.requests[-1]
    assert request["job_context_digest"] == _context().digest
    assert request["subject_hotkey"] == "worker-hotkey"
    assert request["tdx_evidence"]["kind"] == "tdx"
    assert request["gpu_evidence"]["kind"] == "gpu_cc"


def test_trustee_adapter_rejects_mismatched_output_and_input_envelopes() -> None:
    with pytest.raises(TrusteeAdapterError, match="not admissible"):
        _adapter(Runner(mismatch="job_context_digest")).verify(
            context=_context(),
            nonce=NONCE,
            channel_binding=BINDING,
            tdx_evidence=_evidence(EvidenceKind.TDX),
            gpu_evidence=_evidence(EvidenceKind.GPU_CC),
        )
    wrong_hotkey = _evidence(EvidenceKind.GPU_CC)
    object.__setattr__(wrong_hotkey, "miner_hotkey", "other-hotkey")
    with pytest.raises(TrusteeAdapterError, match="envelope"):
        _adapter(Runner()).verify(
            context=_context(),
            nonce=NONCE,
            channel_binding=BINDING,
            tdx_evidence=_evidence(EvidenceKind.TDX),
            gpu_evidence=wrong_hotkey,
        )


@pytest.mark.parametrize(
    "claim",
    (
        "same_guest_verified",
        "gpu_cc_mode_verified",
        "gpu_ready_state_verified",
        "measurement_policy_verified",
        "runtime_isolation_verified",
        "secret_release_authorized",
    ),
)
def test_trustee_adapter_requires_every_security_claim(claim: str) -> None:
    with pytest.raises(TrusteeAdapterError, match="not admissible"):
        _adapter(Runner(mismatch=claim)).verify(
            context=_context(),
            nonce=NONCE,
            channel_binding=BINDING,
            tdx_evidence=_evidence(EvidenceKind.TDX),
            gpu_evidence=_evidence(EvidenceKind.GPU_CC),
        )


def _verified_manifest(tmp_path: Path):
    seed = bytes(range(32))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    artifacts = []
    for name, role, content, mode in (
        ("trustee-bridge", "executable", b"bridge-v1", 0o700),
        ("ld-linux-x86-64.so.2", "loader", b"loader-v1", 0o600),
        ("libnvat.so", "dependency", b"nvat-v1", 0o600),
    ):
        path = tmp_path / name
        path.write_bytes(content)
        path.chmod(mode)
        artifacts.append(
            {
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "path": str(path),
                "role": role,
            }
        )
    signed = sign_trustee_runtime_manifest(
        {
            "artifacts": artifacts,
            "dependency_closure_complete": True,
            "profile_authority": AUTHORITY,
            "profile_id": PROFILE,
            "release": 1,
            "schema": TRUSTEE_RUNTIME_MANIFEST_SCHEMA,
            "signing_key_id": "trustee-runtime-test",
            "trustee_policy_digest": POLICY,
            "valid_from": "2026-07-21T10:00:00.000000Z",
            "valid_until": "2026-07-22T10:00:00.000000Z",
        },
        seed,
    )
    verified = verify_trustee_runtime_manifest(
        canonical_json(signed),
        {"trustee-runtime-test": public},
        at=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
        require_root_owned=False,
    )
    return verified, artifacts[0]["path"], signed, public


def test_signed_runtime_closure_and_preflight_drive_readiness(tmp_path: Path) -> None:
    manifest, executable, _signed, _public = _verified_manifest(tmp_path)
    runner = Runner(
        artifact_manifest_digest=manifest.digest,
        verifier_digest=manifest.executable_digest,
    )
    adapter = _adapter(
        runner,
        artifact_manifest_digest=manifest.digest,
        runtime_manifest=manifest,
        command=executable,
    )
    assert adapter.production_ready is False
    adapter.preflight()
    assert adapter.production_ready is True
    verdict = adapter.verify(
        context=_context(),
        nonce=NONCE,
        channel_binding=BINDING,
        tdx_evidence=_evidence(EvidenceKind.TDX),
        gpu_evidence=_evidence(EvidenceKind.GPU_CC),
    )
    assert verdict.same_guest_verified is True
    assert verdict.gpu_cc_mode_verified is True
    assert verdict.gpu_ready_state_verified is True
    assert verdict.measurement_policy_verified is True
    assert verdict.runtime_isolation_verified is True
    assert verdict.runtime_manifest_digest == manifest.digest
    assert verdict.verifier_digest == manifest.executable_digest
    assert verdict.digest == "sha256:" + hashlib.sha256(
        verdict.canonical_document
    ).hexdigest()
    assert verdict.launch_eligible is True


def test_signed_runtime_rejects_a_different_verifier_digest(tmp_path: Path) -> None:
    manifest, executable, _signed, _public = _verified_manifest(tmp_path)
    runner = Runner(
        artifact_manifest_digest=manifest.digest,
        verifier_digest="sha256:" + "0" * 64,
    )
    adapter = _adapter(
        runner,
        artifact_manifest_digest=manifest.digest,
        runtime_manifest=manifest,
        command=executable,
    )
    adapter.preflight()
    with pytest.raises(TrusteeAdapterError, match="not admissible"):
        adapter.verify(
            context=_context(),
            nonce=NONCE,
            channel_binding=BINDING,
            tdx_evidence=_evidence(EvidenceKind.TDX),
            gpu_evidence=_evidence(EvidenceKind.GPU_CC),
        )


def test_absent_mismatched_or_invalid_runtime_manifest_stays_closed(tmp_path: Path) -> None:
    manifest, executable, signed, public = _verified_manifest(tmp_path)
    mismatched_digest = "sha256:" + "f" * 64
    adapter = _adapter(
        Runner(artifact_manifest_digest=mismatched_digest),
        artifact_manifest_digest=mismatched_digest,
        runtime_manifest=manifest,
        command=executable,
    )
    adapter.preflight()
    assert adapter.production_ready is False
    tampered = dict(signed)
    tampered["release"] = 2
    with pytest.raises(TrusteeAdapterError, match="signature"):
        verify_trustee_runtime_manifest(
            canonical_json(tampered),
            {"trustee-runtime-test": public},
            at=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
            require_root_owned=False,
        )
