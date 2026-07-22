"""Confidential-GPU job binding, receipt, replay, and capability contracts."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.cc_gpu import (
    CcGpuCapability,
    CcGpuJobContext,
    CcGpuJobReceiptIssuer,
    CcGpuReceiptError,
    CcGpuReceiptReplayGuard,
    _id_material,
    _unsigned_bytes,
    derive_admission_nonce,
    derive_completion_nonce,
    verify_cc_gpu_job_receipt,
)
from cathedral.policy_registry import canonical_json, sign_registry, verify_registry


REGISTRY_SEED = bytes(range(32))
RECEIPT_SEED = bytes(range(32, 64))
ISSUED = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
PROFILE_AUTHORITY = (
    "gpu-profile:gcp-a3-high-h100-tdx-v1@profile=sha256:"
    + "a" * 64
    + "@release=1@registry=sha256:"
    + "b" * 64
)


def _public(seed: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _registry():
    registry_public = Ed25519PrivateKey.from_private_bytes(
        REGISTRY_SEED
    ).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    document = sign_registry(
        {
            "schema": "cathedral_policy_registry_v1",
            "release": 1,
            "generated_at": "2026-07-21T10:00:00Z",
            "valid_from": "2026-07-21T10:00:00Z",
            "valid_until": "2026-07-22T10:00:00Z",
            "signing_key_id": "policy-test",
            "receipt_signing_keys": [
                {
                    "id": "cc-gpu-receipt-test",
                    "algorithm": "ed25519",
                    "public_key_base64": _public(RECEIPT_SEED),
                    "purpose": "assurance_receipt",
                    "status": "active",
                    "status_changed_at": "2026-07-21T10:00:00Z",
                    "valid_from": "2026-07-21T10:00:00Z",
                    "valid_until": "2026-07-22T10:00:00Z",
                    "revoked_at": None,
                    "replacement_key_id": None,
                    "metadata": {"environment": "test"},
                }
            ],
            "profiles": [
                {
                    "id": "cpu-tdx-test",
                    "kind": "cpu_tdx",
                    "status": "active",
                    "status_changed_at": "2026-07-21T10:00:00Z",
                    "valid_from": "2026-07-21T10:00:00Z",
                    "valid_until": "2026-07-22T10:00:00Z",
                    "retire_at": None,
                    "measurements": ["measurement"],
                    "runtime_measurements": ["runtime"],
                    "allowed_firmware": [],
                    "min_tcb": 0,
                    "tdx_allowed_tcb_statuses": ["UpToDate"],
                    "tdx_allowed_advisories": [],
                    "metadata": {"environment": "test"},
                }
            ],
            "metadata": {"environment": "test"},
        },
        REGISTRY_SEED,
    )
    return verify_registry(
        canonical_json(document),
        {"policy-test": registry_public},
        now=ISSUED,
        max_age_seconds=86400,
    )


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _context(**changes) -> CcGpuJobContext:
    values = {
        "worker_id": "11111111-1111-4111-8111-111111111111",
        "subject_hotkey": "worker-hotkey",
        "job_id": "22222222-2222-4222-8222-222222222222",
        "attempt_id": "33333333-3333-4333-8333-333333333333",
        "profile_id": "gcp-a3-high-h100-tdx-v1",
        "provider": "gcp",
        "machine_type": "a3-highgpu-1g",
        "zone": "us-central1-a",
        "cpu_tee": "intel_tdx",
        "gpu_model": "nvidia_h100_80gb",
        "gpu_count": 1,
        "provisioning_model": "spot",
        "profile_authority": PROFILE_AUTHORITY,
        "image_digest": _digest("3"),
        "policy_digest": _digest("4"),
        "input_digest": _digest("5"),
        "model_digest": _digest("6"),
    }
    values.update(changes)
    return CcGpuJobContext(**values)


def _issuer() -> CcGpuJobReceiptIssuer:
    return CcGpuJobReceiptIssuer(
        _registry(),
        "cc-gpu-receipt-test",
        RECEIPT_SEED,
        clock=lambda: ISSUED,
    )


def _issue(
    *,
    context: CcGpuJobContext | None = None,
    issued_at: datetime = ISSUED,
    **overrides,
):
    values = {
        "context": context or _context(),
        "admission_bundle_digest": _digest("7"),
        "admission_nonce_digest": _digest("3"),
        "admission_cpu_evidence_digest": _digest("8"),
        "admission_gpu_evidence_digest": _digest("9"),
        "admission_gpu_identity_set_digest": _digest("1"),
        "completion_bundle_digest": _digest("a"),
        "completion_nonce_digest": _digest("4"),
        "completion_cpu_evidence_digest": _digest("b"),
        "completion_gpu_evidence_digest": _digest("c"),
        "completion_gpu_identity_set_digest": _digest("1"),
        "channel_binding_digest": _digest("d"),
        "result_digest": _digest("e"),
        "artifact_manifest_digest": _digest("f"),
        "secret_release_grant_digest": _digest("2"),
        "deletion_evidence_digest": _digest("0"),
        "issued_at": issued_at,
    }
    values.update(overrides)
    return _issuer().issue(**values)


def _resign(document: dict[str, object]) -> bytes:
    document.pop("signature", None)
    document.pop("receipt_id", None)
    document["receipt_id"] = "cc-gpu-receipt-sha256:" + hashlib.sha256(
        _id_material(document)
    ).hexdigest()
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(
            Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED).sign(
                _unsigned_bytes(document)
            )
        ).decode("ascii"),
    }
    return canonical_json(document)


def test_job_context_and_nonces_are_attempt_and_output_bound() -> None:
    context = _context()
    changed_attempt = replace(
        context, attempt_id="44444444-4444-4444-8444-444444444444"
    )
    assert context.digest != changed_attempt.digest
    assert derive_admission_nonce(b"x" * 32, context) != derive_admission_nonce(
        b"x" * 32, changed_attempt
    )
    assert derive_admission_nonce(b"x" * 32, context) != derive_admission_nonce(
        b"y" * 32, context
    )
    completion = derive_completion_nonce(
        b"z" * 32,
        context,
        admission_bundle_digest=_digest("7"),
        result_digest=_digest("e"),
        artifact_manifest_digest=_digest("f"),
    )
    assert completion != derive_completion_nonce(
        b"z" * 32,
        context,
        admission_bundle_digest=_digest("7"),
        result_digest=_digest("1"),
        artifact_manifest_digest=_digest("f"),
    )


def test_completed_receipt_round_trip_and_exact_class() -> None:
    receipt = _issue()
    verified = verify_cc_gpu_job_receipt(
        receipt.receipt_bytes,
        _registry(),
        allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
        at=ISSUED + timedelta(seconds=1),
    )
    assert verified.receipt_id == receipt.receipt_id
    assert verified.document["execution_class"] == "cc_gpu"
    assert verified.document["outcome"] == "completed"
    assert verified.document["deletion_confirmed"] is True


def test_capability_stays_unavailable_until_signed_live_proof_contract_exists() -> None:
    unavailable = CcGpuCapability()
    assert unavailable.availability == "unavailable"
    assert unavailable.launch_gate == "NOT PROVEN"
    assert unavailable.customer_jobs is False
    with pytest.raises(CcGpuReceiptError, match="inconsistent"):
        CcGpuCapability(
            availability="available",
            launch_gate="PASS",
            customer_jobs=True,
            live_evidence_digest=_digest("a"),
        )


def test_stale_receipt_fails_closed() -> None:
    with pytest.raises(CcGpuReceiptError, match="stale"):
        verify_cc_gpu_job_receipt(
            _issue().receipt_bytes,
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=300),
        )


def test_job_context_mismatch_fails_even_with_valid_signature() -> None:
    document = dict(_issue().document)
    document["job_id"] = "99999999-9999-4999-8999-999999999999"
    with pytest.raises(CcGpuReceiptError, match="context digest"):
        verify_cc_gpu_job_receipt(
            _resign(document),
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=1),
        )


def test_subject_hotkey_swap_invalidates_job_context() -> None:
    document = dict(_issue().document)
    document["subject_hotkey"] = "different-hotkey"
    with pytest.raises(CcGpuReceiptError, match="context digest"):
        verify_cc_gpu_job_receipt(
            _resign(document),
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=1),
        )


def test_replay_duplicate_attempt_and_evidence_reuse_fail_closed() -> None:
    guard = CcGpuReceiptReplayGuard()
    first = _issue()
    verify_cc_gpu_job_receipt(
        first.receipt_bytes,
        _registry(),
        allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
        at=ISSUED + timedelta(seconds=2),
        replay_guard=guard,
    )
    with pytest.raises(CcGpuReceiptError, match="already ingested"):
        verify_cc_gpu_job_receipt(
            first.receipt_bytes,
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=2),
            replay_guard=guard,
        )
    second = _issue(issued_at=ISSUED + timedelta(seconds=1))
    with pytest.raises(CcGpuReceiptError, match="already has a receipt"):
        verify_cc_gpu_job_receipt(
            second.receipt_bytes,
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=2),
            replay_guard=guard,
        )
    different_attempt = replace(
        _context(),
        worker_id="44444444-4444-4444-8444-444444444444",
        job_id="55555555-5555-4555-8555-555555555555",
        attempt_id="66666666-6666-4666-8666-666666666666",
    )
    unique = {
        name: "sha256:" + hashlib.sha256(name.encode()).hexdigest()
        for name in (
            "admission_bundle_digest",
            "admission_nonce_digest",
            "admission_cpu_evidence_digest",
            "admission_gpu_evidence_digest",
            "completion_bundle_digest",
            "completion_nonce_digest",
            "completion_cpu_evidence_digest",
            "completion_gpu_evidence_digest",
        )
    }
    third = _issue(
        context=different_attempt,
        issued_at=ISSUED + timedelta(seconds=2),
        **unique,
    )
    with pytest.raises(CcGpuReceiptError, match="evidence was reused"):
        verify_cc_gpu_job_receipt(
            third.receipt_bytes,
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=3),
            replay_guard=guard,
        )


@pytest.mark.parametrize(
    "reused_field",
    (
        "admission_nonce_digest",
        "completion_nonce_digest",
        "secret_release_grant_digest",
        "deletion_evidence_digest",
    ),
)
def test_replay_guard_claims_non_evidence_job_proofs(reused_field: str) -> None:
    guard = CcGpuReceiptReplayGuard()
    first = _issue()
    verify_cc_gpu_job_receipt(
        first.receipt_bytes,
        _registry(),
        allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
        at=ISSUED + timedelta(seconds=1),
        replay_guard=guard,
    )
    guarded_fields = (
        "admission_bundle_digest",
        "admission_nonce_digest",
        "admission_cpu_evidence_digest",
        "admission_gpu_evidence_digest",
        "completion_bundle_digest",
        "completion_nonce_digest",
        "completion_cpu_evidence_digest",
        "completion_gpu_evidence_digest",
        "secret_release_grant_digest",
        "deletion_evidence_digest",
    )
    unique = {
        name: "sha256:" + hashlib.sha256(f"candidate:{name}".encode()).hexdigest()
        for name in guarded_fields
    }
    unique[reused_field] = first.document[reused_field]
    candidate = _issue(
        context=replace(
            _context(),
            worker_id="44444444-4444-4444-8444-444444444444",
            job_id="55555555-5555-4555-8555-555555555555",
            attempt_id="66666666-6666-4666-8666-666666666666",
        ),
        issued_at=ISSUED + timedelta(seconds=1),
        **unique,
    )
    with pytest.raises(CcGpuReceiptError, match="evidence was reused"):
        verify_cc_gpu_job_receipt(
            candidate.receipt_bytes,
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=2),
            replay_guard=guard,
        )


def test_gpu_identity_can_be_reused_by_a_distinct_real_job() -> None:
    guard = CcGpuReceiptReplayGuard()
    first = _issue()
    verify_cc_gpu_job_receipt(
        first.receipt_bytes,
        _registry(),
        allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
        at=ISSUED + timedelta(seconds=1),
        replay_guard=guard,
    )
    guarded_fields = (
        "admission_bundle_digest",
        "admission_nonce_digest",
        "admission_cpu_evidence_digest",
        "admission_gpu_evidence_digest",
        "completion_bundle_digest",
        "completion_nonce_digest",
        "completion_cpu_evidence_digest",
        "completion_gpu_evidence_digest",
        "secret_release_grant_digest",
        "deletion_evidence_digest",
    )
    unique = {
        name: "sha256:" + hashlib.sha256(f"next-job:{name}".encode()).hexdigest()
        for name in guarded_fields
    }
    candidate = _issue(
        context=replace(
            _context(),
            worker_id="44444444-4444-4444-8444-444444444444",
            job_id="55555555-5555-4555-8555-555555555555",
            attempt_id="66666666-6666-4666-8666-666666666666",
        ),
        issued_at=ISSUED + timedelta(seconds=1),
        **unique,
    )
    verified = verify_cc_gpu_job_receipt(
        candidate.receipt_bytes,
        _registry(),
        allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
        at=ISSUED + timedelta(seconds=2),
        replay_guard=guard,
    )
    assert (
        verified.document["admission_gpu_identity_set_digest"]
        == first.document["admission_gpu_identity_set_digest"]
    )


def test_partial_and_hybrid_receipts_are_rejected() -> None:
    partial = dict(_issue().document)
    partial.pop("completion_gpu_evidence_digest")
    with pytest.raises(CcGpuReceiptError, match="unknown fields"):
        verify_cc_gpu_job_receipt(
            _resign(partial),
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=1),
        )
    hybrid = dict(_issue().document)
    hybrid["execution_class"] = "hybrid_gpu_preview"
    with pytest.raises(CcGpuReceiptError, match="hybrid"):
        verify_cc_gpu_job_receipt(
            _resign(hybrid),
            _registry(),
            allowed_profile_authorities=frozenset({PROFILE_AUTHORITY}),
            at=ISSUED + timedelta(seconds=1),
        )


def test_duplicate_or_unconfirmed_completion_cannot_be_issued() -> None:
    with pytest.raises(CcGpuReceiptError, match="unique"):
        _issuer().issue(
            context=_context(),
            admission_bundle_digest=_digest("7"),
            admission_nonce_digest=_digest("3"),
            admission_cpu_evidence_digest=_digest("7"),
            admission_gpu_evidence_digest=_digest("9"),
            admission_gpu_identity_set_digest=_digest("1"),
            completion_bundle_digest=_digest("a"),
            completion_nonce_digest=_digest("4"),
            completion_cpu_evidence_digest=_digest("b"),
            completion_gpu_evidence_digest=_digest("c"),
            completion_gpu_identity_set_digest=_digest("1"),
            channel_binding_digest=_digest("d"),
            result_digest=_digest("e"),
            artifact_manifest_digest=_digest("f"),
            secret_release_grant_digest=_digest("2"),
            deletion_evidence_digest=_digest("0"),
        )
    with pytest.raises(CcGpuReceiptError, match="confirmed deletion"):
        _issuer().issue(
            context=_context(),
            admission_bundle_digest=_digest("7"),
            admission_nonce_digest=_digest("3"),
            admission_cpu_evidence_digest=_digest("8"),
            admission_gpu_evidence_digest=_digest("9"),
            admission_gpu_identity_set_digest=_digest("1"),
            completion_bundle_digest=_digest("a"),
            completion_nonce_digest=_digest("4"),
            completion_cpu_evidence_digest=_digest("b"),
            completion_gpu_evidence_digest=_digest("c"),
            completion_gpu_identity_set_digest=_digest("1"),
            channel_binding_digest=_digest("d"),
            result_digest=_digest("e"),
            artifact_manifest_digest=_digest("f"),
            secret_release_grant_digest=_digest("2"),
            deletion_evidence_digest=_digest("0"),
            deletion_confirmed=False,
        )
    with pytest.raises(CcGpuReceiptError, match="identity sets must match"):
        _issuer().issue(
            context=_context(),
            admission_bundle_digest=_digest("7"),
            admission_nonce_digest=_digest("3"),
            admission_cpu_evidence_digest=_digest("8"),
            admission_gpu_evidence_digest=_digest("9"),
            admission_gpu_identity_set_digest=_digest("1"),
            completion_bundle_digest=_digest("a"),
            completion_nonce_digest=_digest("4"),
            completion_cpu_evidence_digest=_digest("b"),
            completion_gpu_evidence_digest=_digest("c"),
            completion_gpu_identity_set_digest=_digest("2"),
            channel_binding_digest=_digest("d"),
            result_digest=_digest("e"),
            artifact_manifest_digest=_digest("f"),
            secret_release_grant_digest=_digest("2"),
            deletion_evidence_digest=_digest("0"),
        )
