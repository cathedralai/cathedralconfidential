"""Durable canonical assurance receipt contracts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.assurance import (
    AssuranceDimension,
    ClaimStatus,
    ReasonCategory,
    attestation_claims,
    evaluated_claim,
    with_verified_channel,
)
from cathedral.cli import _load_receipt_private_seed, cmd_receipt_verify, main as cli_main
from cathedral.common import Attested, Policy, Tier
from cathedral.ledger import Ledger, LedgerError
from cathedral.lifecycle import (
    LifecycleReason,
    LifecycleSnapshot,
    WorkerLifecycleState,
)
from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistryState,
    canonical_json,
    sign_registry,
    verify_registry,
)
from cathedral.receipt import (
    MAX_RECEIPT_BYTES,
    ReceiptError,
    ReceiptIssuer,
    parse_receipt_json,
    verify_receipt,
)
from cathedral.runtime import SAT_WORK_POLICY_DIGEST
from cathedral.score_class import ScoreClassError, export_score_class_report


REGISTRY_SEED = bytes(range(32))
RECEIPT_SEED_1 = bytes(range(32, 64))
RECEIPT_SEED_2 = bytes(range(64, 96))
REGISTRY_PUBLIC = Ed25519PrivateKey.from_private_bytes(
    REGISTRY_SEED
).public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
TRUSTED = {"cathedral-policy-test-1": REGISTRY_PUBLIC}
ISSUED = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
ISSUED_TEXT = "2026-07-17T12:00:00.000000Z"
CHALLENGE_ID = "a" * 64
MANIFEST_DIGEST = "sha256:" + "b" * 64


def _public(seed: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _receipt_key(
    key_id: str,
    seed: bytes,
    *,
    status: str = "active",
    changed: str = "2026-07-17T01:00:00Z",
    revoked_at: str | None = None,
    replacement: str | None = None,
    valid_from: str = "2026-07-17T01:00:00Z",
    valid_until: str = "2026-07-20T00:00:00Z",
) -> dict[str, object]:
    return {
        "id": key_id,
        "algorithm": "ed25519",
        "public_key_base64": _public(seed),
        "purpose": "assurance_receipt",
        "status": status,
        "status_changed_at": changed,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "revoked_at": revoked_at,
        "replacement_key_id": replacement,
        "metadata": {"environment": "test-only"},
    }


def _registry_document(
    *,
    release: int = 1,
    receipt_keys: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    unsigned = {
        "schema": "cathedral_policy_registry_v1",
        "release": release,
        "generated_at": "2026-07-17T00:00:00Z",
        "valid_from": "2026-07-17T01:00:00Z",
        "valid_until": "2026-07-20T00:00:00Z",
        "signing_key_id": "cathedral-policy-test-1",
        "receipt_signing_keys": receipt_keys
        if receipt_keys is not None
        else [_receipt_key("receipt-test-1", RECEIPT_SEED_1)],
        "profiles": [
            {
                "id": "cpu-tdx-sample-v1",
                "kind": "cpu_tdx",
                "status": "active",
                "status_changed_at": "2026-07-17T01:00:00Z",
                "valid_from": "2026-07-17T01:00:00Z",
                "valid_until": "2026-07-20T00:00:00Z",
                "retire_at": None,
                "measurements": ["tdx-measurement-sha256:sample-v1"],
                "runtime_measurements": ["runtime-sha256:sample-v1"],
                "allowed_firmware": [],
                "min_tcb": 0,
                "tdx_allowed_tcb_statuses": ["UpToDate"],
                "tdx_allowed_advisories": [],
                "metadata": {"description": "test CPU profile"},
            }
        ],
        "metadata": {"purpose": "receipt tests"},
    }
    return sign_registry(unsigned, REGISTRY_SEED)


def _snapshot(
    *,
    release: int = 1,
    receipt_keys: list[dict[str, object]] | None = None,
    now: datetime = ISSUED,
):
    return verify_registry(
        canonical_json(
            _registry_document(release=release, receipt_keys=receipt_keys)
        ),
        TRUSTED,
        now=now,
        max_age_seconds=172800,
    )


def _claims(policy: Policy, *, work_status: ClaimStatus = ClaimStatus.PASSED):
    claims = attestation_claims(b"raw-quote-secret", policy, verified_at=ISSUED_TEXT)
    claims = with_verified_channel(
        claims,
        b"channel-binding-material",
        verified_at=ISSUED_TEXT,
    )
    work = evaluated_claim(
        work_status,
        b"work-result-material",
        SAT_WORK_POLICY_DIGEST,
        verified_at=ISSUED_TEXT,
        reason=(
            None
            if work_status is ClaimStatus.PASSED
            else ReasonCategory.WORK_INVALID
        ),
    )
    return claims.with_claim(AssuranceDimension.WORK, work)


def _attested(claims) -> Attested:
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id="tdx-platform-sha256:" + "c" * 64,
        measurement="tdx-measurement-sha256:sample-v1",
        tcb=1,
        tcb_status="UpToDate",
        advisory_ids=(),
        debug_enabled=False,
        collateral_current=True,
        tcb_svn="01" * 16,
        policy_mode="strict",
        assurance=claims,
    )


def _worker_lifecycle(policy: Policy, claims, hotkey: str) -> LifecycleSnapshot:
    return LifecycleSnapshot(
        hotkey=hotkey,
        state=WorkerLifecycleState.ATTESTED,
        generation=1,
        revision=2,
        event_id=2,
        reason=LifecycleReason.ATTESTATION_VERIFIED,
        state_changed_at=ISSUED,
        evidence_verified_at=ISSUED,
        evidence_expires_at=ISSUED + timedelta(hours=1),
        measurement="tdx-measurement-sha256:sample-v1",
        evidence_digest=claims.hardware.evidence_digest,
        policy_digest=claims.software.policy_digest,
        policy_registry_release=policy.registry_release,
        policy_registry_digest=policy.registry_digest,
    )


def _issued_receipt(
    *,
    work_status: ClaimStatus = ClaimStatus.PASSED,
    epoch_id: int = 7,
    source_epoch: int = 11,
    subject_hotkey: str = "public-hotkey",
    challenge_id: str = CHALLENGE_ID,
    work_units: float | None = None,
):
    snapshot = _snapshot()
    policy = snapshot.to_policy(at=ISSUED)
    claims = _claims(policy, work_status=work_status)
    attested = _attested(claims)
    receipt = ReceiptIssuer(snapshot, "receipt-test-1", RECEIPT_SEED_1).issue(
        epoch_id=epoch_id,
        source_epoch=source_epoch,
        subject_hotkey=subject_hotkey,
        attested=attested,
        policy=policy,
        assurance=claims,
        worker_lifecycle=_worker_lifecycle(policy, claims, subject_hotkey),
        challenge_id=challenge_id,
        manifest_digest=MANIFEST_DIGEST,
        work_units=(
            work_units
            if work_units is not None
            else (3.5 if work_status is ClaimStatus.PASSED else 0.0)
        ),
        issued_at=ISSUED,
    )
    return snapshot, policy, claims, receipt


def _resign(document: dict[str, object]) -> bytes:
    id_material = dict(document)
    id_material.pop("receipt_id", None)
    id_material.pop("signature", None)
    document["receipt_id"] = "receipt-sha256:" + hashlib.sha256(
        canonical_json(id_material)
    ).hexdigest()
    unsigned = dict(document)
    unsigned.pop("signature", None)
    signature = Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED_1).sign(
        canonical_json(unsigned)
    )
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return canonical_json(document)


def _reidentify(document: dict[str, object]) -> None:
    id_material = dict(document)
    id_material.pop("receipt_id", None)
    id_material.pop("signature", None)
    document["receipt_id"] = "receipt-sha256:" + hashlib.sha256(
        canonical_json(id_material)
    ).hexdigest()


def test_golden_receipt_signature_canonicalization_and_offline_verification():
    snapshot, _policy, _claims_value, receipt = _issued_receipt()
    verified = verify_receipt(receipt.receipt_bytes, snapshot)

    assert verified.receipt_id == receipt.receipt_id
    assert verified.receipt_bytes == receipt.receipt_bytes
    assert verified.receipt_digest == receipt.receipt_digest
    assert receipt.receipt_id == (
        "receipt-sha256:b0a9956a73816a273cf3d23677357df3eec78aaf101753cfd651f51111e4b344"
    )
    assert receipt.receipt_digest == (
        "sha256:82748edd31b321883703473ab0fb05b06f74a8fbdca3b0acd569314f45997ffc"
    )
    assert (
        Path("tests/fixtures/assurance-receipt-v2.json").read_bytes().rstrip(b"\n")
        == receipt.receipt_bytes
    )
    assert receipt.document["work"]["work_units"] == "3.5"
    assert hashlib.sha256(receipt.receipt_bytes).hexdigest() == receipt.receipt_digest.removeprefix(
        "sha256:"
    )


def test_historical_v1_receipt_remains_offline_verifiable():
    receipt_bytes = Path("tests/fixtures/assurance-receipt-v1.json").read_bytes().rstrip(
        b"\n"
    )
    verified = verify_receipt(receipt_bytes, _snapshot())
    assert verified.document["schema"] == "cathedral_assurance_receipt_v1"
    assert verified.receipt_id == (
        "receipt-sha256:0277d2aa2f85999e5883f5d23ea9616ae04b881fda71daf58df3bd8c66863fec"
    )


def test_v2_receipt_rejects_a_known_reason_for_the_wrong_worker_state():
    snapshot, _policy, _claims_value, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    document["lifecycle"]["worker_reason"] = "enrolled"

    with pytest.raises(ReceiptError, match="lifecycle state is invalid"):
        verify_receipt(_resign(document), snapshot)


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        ("schema", lambda value: value.update(schema="cathedral_assurance_receipt_v3")),
        ("receipt_id", lambda value: value.update(receipt_id="receipt-sha256:" + "0" * 64)),
        ("epoch_id", lambda value: value.update(epoch_id=8)),
        ("source_epoch", lambda value: value.update(source_epoch=12)),
        ("subject_hotkey", lambda value: value.update(subject_hotkey="other")),
        (
            "platform_pseudonym",
            lambda value: value.update(platform_pseudonym="platform-sha256:" + "0" * 64),
        ),
        ("policy_registry_release", lambda value: value.update(policy_registry_release=2)),
        (
            "policy_registry_digest",
            lambda value: value.update(policy_registry_digest="sha256:" + "0" * 64),
        ),
        ("policy_profile_ids", lambda value: value.update(policy_profile_ids=["other"])),
        ("measurement", lambda value: value.update(measurement="other")),
        ("tcb", lambda value: value["tcb"].update(status="OutOfDate")),
        (
            "channel",
            lambda value: value["channel"].update(binding_digest="sha256:" + "0" * 64),
        ),
        ("work", lambda value: value["work"].update(work_units="4")),
        (
            "assurance",
            lambda value: value["assurance"]["claims"]["work"].update(
                evidence_digest="sha256:" + "1" * 64
            ),
        ),
        ("lifecycle", lambda value: value["lifecycle"].update(state="revoked")),
        (
            "lifecycle_reason",
            lambda value: value["lifecycle"].update(worker_reason="enrolled"),
        ),
        ("issued_at", lambda value: value.update(issued_at="2026-07-17T12:00:01.000000Z")),
        ("signing_key_id", lambda value: value.update(signing_key_id="unknown-key")),
        (
            "signature",
            lambda value: value["signature"].update(
                value_base64=base64.b64encode(bytes(64)).decode("ascii")
            ),
        ),
    ],
)
def test_mutation_of_every_signed_receipt_field_is_rejected(field, mutation):
    snapshot, _policy, _claims_value, receipt = _issued_receipt()
    document = json.loads(receipt.receipt_bytes)
    mutation(document)
    if field not in {"receipt_id", "signature"}:
        _reidentify(document)

    with pytest.raises(ReceiptError):
        verify_receipt(canonical_json(document), snapshot)


def test_duplicate_unknown_version_float_and_oversized_receipts_fail_closed():
    snapshot, _policy, _claims_value, receipt = _issued_receipt()
    with pytest.raises(ReceiptError, match="duplicate"):
        parse_receipt_json('{"schema":"x","schema":"y"}')
    with pytest.raises(ReceiptError, match="maximum encoded size"):
        parse_receipt_json(b" " * (MAX_RECEIPT_BYTES + 1))

    document = json.loads(receipt.receipt_bytes)
    document["future_critical"] = True
    with pytest.raises(ReceiptError, match="missing, unknown"):
        verify_receipt(canonical_json(document), snapshot)

    document = json.loads(receipt.receipt_bytes)
    document["schema"] = "cathedral_assurance_receipt_v3"
    with pytest.raises(ReceiptError, match="unsupported"):
        verify_receipt(canonical_json(document), snapshot)

    document = json.loads(receipt.receipt_bytes)
    document["schema"] = []
    with pytest.raises(ReceiptError, match="unsupported"):
        verify_receipt(canonical_json(document), snapshot)

    with pytest.raises(ReceiptError, match="floating-point"):
        parse_receipt_json('{"work_units":1.5}')
    with pytest.raises(ReceiptError, match="integer exceeds"):
        parse_receipt_json('{"epoch_id":9223372036854775808}')
    with pytest.raises(ReceiptError, match="UTF-8 JSON"):
        parse_receipt_json('{"epoch_id":01}')
    with pytest.raises(ReceiptError, match="invalid Unicode"):
        parse_receipt_json('{"subject_hotkey":"\\ud800"}')

    with pytest.raises(ReceiptError, match="not canonical"):
        verify_receipt(
            json.dumps(json.loads(receipt.receipt_bytes), indent=2),
            snapshot,
        )


def test_unicode_and_canonical_timestamp_rules_are_stable():
    snapshot, _policy, _claims_value, receipt = _issued_receipt(
        subject_hotkey="caf\u00e9-validator"
    )
    assert b"caf\\u00e9-validator" in receipt.receipt_bytes
    verified = verify_receipt(receipt.receipt_bytes, snapshot)
    assert verified.document["subject_hotkey"] == "caf\u00e9-validator"

    document = json.loads(receipt.receipt_bytes)
    document["issued_at"] = "2026-07-17T12:00:00Z"
    with pytest.raises(ReceiptError, match="canonical UTC"):
        verify_receipt(_resign(document), snapshot)

    document = json.loads(receipt.receipt_bytes)
    document["issued_at"] = "2026-07-17T11:59:59.000000Z"
    with pytest.raises(ReceiptError, match="later than receipt"):
        verify_receipt(_resign(document), snapshot)


def test_claim_digest_presence_and_explicit_zero_are_enforced():
    snapshot, _policy, _claims_value, receipt = _issued_receipt(
        work_status=ClaimStatus.FAILED
    )
    assert receipt.document["work"]["work_units"] == "0"
    assert verify_receipt(receipt.receipt_bytes, snapshot)

    document = json.loads(receipt.receipt_bytes)
    document["assurance"]["claims"]["work"]["evidence_digest"] = None
    with pytest.raises(ReceiptError, match="claims are invalid"):
        verify_receipt(_resign(document), snapshot)

    document = json.loads(receipt.receipt_bytes)
    document["work"]["work_units"] = "1"
    with pytest.raises(ReceiptError, match="zero units"):
        verify_receipt(_resign(document), snapshot)


def test_public_receipt_does_not_leak_raw_evidence_platform_or_credentials():
    _snapshot_value, _policy, _claims_value, receipt = _issued_receipt()
    forbidden = (
        b"raw-quote-secret",
        b"tdx-platform-sha256:",
        b"bearer-token",
        b"private.example.internal",
        b"data-key",
    )
    assert all(value not in receipt.receipt_bytes for value in forbidden)
    assert b"platform-sha256:" in receipt.receipt_bytes


def test_key_rotation_overlap_retirement_and_compromise_revocation(tmp_path: Path):
    original = _snapshot()
    _snapshot_value, _policy, _claims_value, receipt = _issued_receipt()
    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    state.accept(original)

    retired_old = _receipt_key(
        "receipt-test-1",
        RECEIPT_SEED_1,
        status="retired",
        changed="2026-07-18T00:00:00Z",
        replacement="receipt-test-2",
    )
    replacement = _receipt_key("receipt-test-2", RECEIPT_SEED_2)
    rotated = _snapshot(
        release=2,
        receipt_keys=[retired_old, replacement],
        now=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
    )
    state.accept(rotated)
    assert verify_receipt(
        receipt.receipt_bytes, original, key_registry=rotated
    ).receipt_id == receipt.receipt_id

    revoked_old = _receipt_key(
        "receipt-test-1",
        RECEIPT_SEED_1,
        status="revoked",
        changed="2026-07-18T12:00:00Z",
        revoked_at="2026-07-18T12:00:00Z",
        replacement="receipt-test-2",
    )
    revoked = _snapshot(
        release=3,
        receipt_keys=[revoked_old, replacement],
        now=datetime(2026, 7, 18, 13, 0, 0, tzinfo=UTC),
    )
    state.accept(revoked)
    with pytest.raises(ReceiptError, match="revoked"):
        verify_receipt(receipt.receipt_bytes, original, key_registry=revoked)


def test_receipt_key_material_is_immutable_across_registry_releases(tmp_path: Path):
    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    state.accept(_snapshot())
    changed_key = _receipt_key("receipt-test-1", RECEIPT_SEED_2)
    changed = _snapshot(release=2, receipt_keys=[changed_key])

    with pytest.raises(PolicyRegistryError, match="key material changed"):
        state.accept(changed)

    shortened = _snapshot(
        release=2,
        receipt_keys=[
            _receipt_key(
                "receipt-test-1",
                RECEIPT_SEED_1,
                valid_until="2026-07-19T00:00:00Z",
            )
        ],
    )
    with pytest.raises(PolicyRegistryError, match="validity window changed"):
        state.accept(shortened)


def test_unknown_and_expired_receipt_signing_keys_fail_closed():
    snapshot = _snapshot()
    with pytest.raises(ReceiptError, match="absent"):
        ReceiptIssuer(snapshot, "unknown-key", RECEIPT_SEED_1)

    expiring = _receipt_key(
        "receipt-test-1",
        RECEIPT_SEED_1,
        valid_until="2026-07-18T00:00:00Z",
    )
    expiring_snapshot = _snapshot(receipt_keys=[expiring])
    policy = expiring_snapshot.to_policy(at=ISSUED)
    claims = _claims(policy)
    issuer = ReceiptIssuer(
        expiring_snapshot,
        "receipt-test-1",
        RECEIPT_SEED_1,
    )
    with pytest.raises(ReceiptError, match="not active"):
        issuer.issue(
            epoch_id=7,
            source_epoch=11,
            subject_hotkey="public-hotkey",
            attested=_attested(claims),
            policy=policy,
            assurance=claims,
            worker_lifecycle=_worker_lifecycle(policy, claims, "public-hotkey"),
            challenge_id=CHALLENGE_ID,
            manifest_digest=MANIFEST_DIGEST,
            work_units=3.5,
            issued_at=datetime(2026, 7, 18, 0, 0, 0, tzinfo=UTC),
        )

    valid = issuer.issue(
        epoch_id=7,
        source_epoch=11,
        subject_hotkey="public-hotkey",
        attested=_attested(claims),
        policy=policy,
        assurance=claims,
        worker_lifecycle=_worker_lifecycle(policy, claims, "public-hotkey"),
        challenge_id=CHALLENGE_ID,
        manifest_digest=MANIFEST_DIGEST,
        work_units=3.5,
        issued_at=ISSUED,
    )
    expired = json.loads(valid.receipt_bytes)
    expired["issued_at"] = "2026-07-18T00:00:00.000000Z"
    expired["lifecycle"]["worker_evidence_expires_at"] = (
        "2026-07-18T01:00:00.000000Z"
    )
    with pytest.raises(ReceiptError, match="out of window"):
        verify_receipt(_resign(expired), expiring_snapshot)


def test_receipt_private_seed_file_is_bounded_and_permission_checked(tmp_path: Path):
    key_path = tmp_path / "receipt.key"
    key_path.write_bytes(base64.b64encode(RECEIPT_SEED_1) + b"\n")
    key_path.chmod(0o600)
    assert _load_receipt_private_seed(
        str(key_path), production_mode=True
    ) == RECEIPT_SEED_1

    key_path.chmod(0o644)
    with pytest.raises(ValueError, match="group/world"):
        _load_receipt_private_seed(str(key_path), production_mode=True)
    key_path.chmod(0o600)

    symlink = tmp_path / "receipt-link.key"
    symlink.symlink_to(key_path)
    with pytest.raises(ValueError, match="non-symlink"):
        _load_receipt_private_seed(str(symlink), production_mode=False)

    oversized = tmp_path / "oversized.key"
    oversized.write_bytes(b"A" * 257)
    oversized.chmod(0o600)
    with pytest.raises(ValueError, match="32-byte base64 seed"):
        _load_receipt_private_seed(str(oversized), production_mode=True)


def test_existing_policy_state_schema_migrates_receipt_key_checkpoint(tmp_path: Path):
    path = tmp_path / "legacy-policy-state.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE policy_registry_state ("
            "singleton INTEGER PRIMARY KEY, release INTEGER NOT NULL, "
            "digest TEXT NOT NULL, profile_states_json TEXT NOT NULL, "
            "accepted_at TEXT NOT NULL)"
        )
    state = PolicyRegistryState(path, minimum_release=1)
    with sqlite3.connect(path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(policy_registry_state)")
        }
    assert "receipt_key_states_json" in columns
    assert state.current() is None


def test_receipt_bytes_persist_atomically_with_work_resolution(tmp_path: Path):
    snapshot = _snapshot()
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    _snapshot_value, receipt_policy, receipt_claims, receipt = _issued_receipt(
        epoch_id=epoch_id
    )
    ledger.issue_challenge(CHALLENGE_ID, "public-hotkey", epoch_id)
    ledger.resolve_challenge_with_receipt(
        CHALLENGE_ID,
        "verified",
        3.5,
        validator_derived=True,
        receipt_id=receipt.receipt_id,
        receipt_body=receipt.receipt_bytes,
        receipt_digest=receipt.receipt_digest,
        issued_at=ISSUED_TEXT,
    )
    stored = ledger.receipt_for_challenge(CHALLENGE_ID)
    assert stored is not None
    assert stored["receipt_body"] == receipt.receipt_bytes
    assert stored["receipt_digest"] == receipt.receipt_digest
    ledger.add_lifecycle_snapshot(
        epoch_id,
        _worker_lifecycle(receipt_policy, receipt_claims, "public-hotkey"),
        snapshot_at=ISSUED_TEXT,
    )

    eligibility_zero = "f" * 64
    ledger.issue_challenge(eligibility_zero, "eligibility-zero", epoch_id)
    _snapshot_value, _policy, _claims_value, zero_receipt = _issued_receipt(
        epoch_id=epoch_id,
        subject_hotkey="eligibility-zero",
        challenge_id=eligibility_zero,
        work_units=0.0,
    )
    ledger.resolve_challenge_with_receipt(
        eligibility_zero,
        "failed",
        0,
        validator_derived=False,
        receipt_id=zero_receipt.receipt_id,
        receipt_body=zero_receipt.receipt_bytes,
        receipt_digest=zero_receipt.receipt_digest,
        issued_at=ISSUED_TEXT,
    )
    assert ledger.receipt_for_challenge(eligibility_zero)["work_status"] == "failed"

    second = "d" * 64
    ledger.issue_challenge(second, "other-hotkey", epoch_id)
    ledger._connection.execute(
        "CREATE TRIGGER simulate_receipt_crash BEFORE INSERT ON assurance_receipts "
        "BEGIN SELECT RAISE(ABORT, 'simulated crash'); END"
    )
    _snapshot_value, _policy, _claims_value, failed_receipt = _issued_receipt(
        work_status=ClaimStatus.FAILED,
        epoch_id=epoch_id,
        subject_hotkey="other-hotkey",
        challenge_id=second,
    )
    with pytest.raises(LedgerError, match="persist receipt atomically"):
        ledger.resolve_challenge_with_receipt(
            second,
            "failed",
            0,
            validator_derived=False,
            receipt_id=failed_receipt.receipt_id,
            receipt_body=failed_receipt.receipt_bytes,
            receipt_digest=failed_receipt.receipt_digest,
            issued_at=ISSUED_TEXT,
        )
    challenge = ledger._connection.execute(
        "SELECT status FROM challenges WHERE challenge_id = ?", (second,)
    ).fetchone()
    assert challenge["status"] == "issued"
    assert ledger.receipt_for_challenge(second) is None


def test_epoch_snapshot_must_match_the_exact_lifecycle_signed_in_receipt(tmp_path: Path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(11)
    _snapshot_value, policy, claims, receipt = _issued_receipt(epoch_id=epoch_id)
    ledger.issue_challenge(CHALLENGE_ID, "public-hotkey", epoch_id)
    ledger.resolve_challenge_with_receipt(
        CHALLENGE_ID,
        "verified",
        3.5,
        validator_derived=True,
        receipt_id=receipt.receipt_id,
        receipt_body=receipt.receipt_bytes,
        receipt_digest=receipt.receipt_digest,
        issued_at=ISSUED_TEXT,
    )
    mismatched = replace(
        _worker_lifecycle(policy, claims, "public-hotkey"),
        revision=3,
        event_id=3,
    )

    with pytest.raises(LedgerError, match="does not match"):
        ledger.add_lifecycle_snapshot(epoch_id, mismatched, snapshot_at=ISSUED_TEXT)


def _completed_receipt_epoch(tmp_path: Path, *, work_units: float = 3.5) -> tuple[Ledger, int]:
    snapshot = _snapshot()
    ledger = Ledger(tmp_path / "score-class-ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        11,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    _snapshot_value, policy, claims, receipt = _issued_receipt(
        epoch_id=epoch_id, work_units=work_units
    )
    ledger.issue_challenge(CHALLENGE_ID, "public-hotkey", epoch_id)
    ledger.resolve_challenge_with_receipt(
        CHALLENGE_ID,
        "verified",
        work_units,
        validator_derived=True,
        receipt_id=receipt.receipt_id,
        receipt_body=receipt.receipt_bytes,
        receipt_digest=receipt.receipt_digest,
        issued_at=ISSUED_TEXT,
    )
    ledger.add_attestation(
        epoch_id,
        "public-hotkey",
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest=claims.hardware.evidence_digest,
        policy_mode="strict",
    )
    ledger.add_lifecycle_snapshot(
        epoch_id,
        _worker_lifecycle(policy, claims, "public-hotkey"),
        snapshot_at=ISSUED_TEXT,
    )
    ledger.complete_epoch(
        epoch_id,
        {"public-hotkey", "zero-hotkey"},
        generated_at=ISSUED_TEXT,
        score_network="local",
        score_netuid=1,
    )
    return ledger, epoch_id


def _export_score_class(
    ledger: Ledger,
    epoch_id: int,
    *,
    generated_at: datetime = ISSUED,
    evidence_base_uri: str | None = None,
    previous_report_id: str | None = None,
) -> bytes:
    return export_score_class_report(
        ledger,
        epoch_id,
        network="local",
        netuid=1,
        class_id="confidential_compute",
        source_id="cathedralconfidential",
        signing_key_id="score-test-1",
        private_key_seed=RECEIPT_SEED_2,
        generated_at=generated_at,
        valid_until=generated_at + timedelta(minutes=5),
        valid_from_block=70,
        valid_until_block=80,
        verifier_digest="sha256:" + "d" * 64,
        evidence_base_uri=evidence_base_uri,
        previous_report_id=previous_report_id,
    )


def _completed_zero_epoch(ledger: Ledger, source_epoch: int) -> int:
    snapshot = _snapshot()
    epoch_id = ledger.begin_epoch(
        source_epoch,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    ledger.complete_epoch(
        epoch_id,
        {"zero-hotkey"},
        generated_at=ISSUED_TEXT,
        score_network="local",
        score_netuid=1,
    )
    return epoch_id


def _two_completed_score_epochs(tmp_path: Path) -> tuple[Path, int, int]:
    path = tmp_path / "score-class-chain.sqlite"
    ledger = Ledger(path)
    first_epoch = _completed_zero_epoch(ledger, 11)
    ledger.mark_published(first_epoch)
    second_epoch = _completed_zero_epoch(ledger, 12)
    ledger.close()
    return path, first_epoch, second_epoch


def test_score_class_export_contains_exact_receipt_provenance_and_zero_revocation(
    tmp_path: Path,
):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path)

    raw = _export_score_class(
        ledger,
        epoch_id,
        evidence_base_uri="https://evidence.example/receipts/",
    )
    document = json.loads(raw)
    rows = {entry["miner_hotkey"]: entry for entry in document["entries"]}
    stored = ledger.receipt_for_challenge(CHALLENGE_ID)

    assert raw == canonical_json(document)
    assert document["schema"] == "cathedral_score_class_report_v1"
    assert (document["network"], document["netuid"]) == ("local", 1)
    assert document["source_epoch"] == 11
    assert rows["public-hotkey"]["metrics"] == {"verified_work_units": "3.5"}
    assert rows["public-hotkey"]["asserted_score"] is None
    assert rows["public-hotkey"]["evidence"] == [
        {
            "kind": "cathedral_assurance_receipt_v2",
            "id": stored["receipt_id"],
            "digest": stored["receipt_digest"],
            "uri": "https://evidence.example/receipts/" + stored["receipt_id"] + ".json",
        }
    ]
    assert rows["zero-hotkey"] == {
        "miner_hotkey": "zero-hotkey",
        "metrics": {"verified_work_units": "0"},
        "asserted_score": None,
        "reason_codes": ["no_verified_work"],
        "evidence": [],
    }


def test_score_class_export_rejects_receiptless_positive_work(tmp_path: Path):
    ledger = Ledger(tmp_path / "legacy-ledger.sqlite")
    epoch_id = ledger.begin_epoch(1)
    ledger.issue_challenge("legacy", "legacy-hotkey", epoch_id)
    ledger.resolve_challenge("legacy", "verified", 1, validator_derived=True)
    ledger.add_attestation(
        epoch_id,
        "legacy-hotkey",
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest="legacy-evidence",
    )
    ledger.complete_epoch(
        epoch_id,
        {"legacy-hotkey"},
        score_network="local",
        score_netuid=1,
    )

    with pytest.raises(ScoreClassError, match="lacks an assurance receipt"):
        _export_score_class(ledger, epoch_id)


def test_score_class_export_rejects_wrong_audience_and_corrupt_receipt(tmp_path: Path):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path)

    with pytest.raises(ScoreClassError, match="audience"):
        export_score_class_report(
            ledger,
            epoch_id,
            network="local",
            netuid=2,
            class_id="confidential_compute",
            source_id="cathedralconfidential",
            signing_key_id="score-test-1",
            private_key_seed=RECEIPT_SEED_2,
            generated_at=ISSUED,
            valid_until=ISSUED + timedelta(minutes=5),
            valid_from_block=70,
            valid_until_block=80,
            verifier_digest="sha256:" + "d" * 64,
        )

    ledger._connection.execute(
        "UPDATE assurance_receipts SET receipt_body = ? WHERE epoch_id = ?",
        (b"{}", epoch_id),
    )
    with pytest.raises(ScoreClassError, match="receipt digest mismatch"):
        _export_score_class(ledger, epoch_id)


def test_score_class_export_replays_exact_first_bytes_and_chains_next_epoch(tmp_path: Path):
    ledger, first_epoch = _completed_receipt_epoch(tmp_path)
    first = _export_score_class(ledger, first_epoch)
    first_document = json.loads(first)

    replay = _export_score_class(
        ledger,
        first_epoch,
        generated_at=ISSUED + timedelta(hours=1),
        evidence_base_uri="https://different.example/receipts/",
    )
    assert replay == first
    assert (
        ledger.get_score_class_export(
            first_epoch,
            network="local",
            netuid=1,
            class_id="confidential_compute",
            source_id="cathedralconfidential",
        )["report_body"]
        == first
    )

    ledger.mark_published(first_epoch)
    snapshot = _snapshot()
    second_epoch = ledger.begin_epoch(
        12,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    ledger.complete_epoch(
        second_epoch,
        {"public-hotkey"},
        generated_at="2026-07-17T12:01:00.000000Z",
        score_network="local",
        score_netuid=1,
    )
    second = _export_score_class(
        ledger,
        second_epoch,
        generated_at=ISSUED + timedelta(minutes=1),
    )

    assert json.loads(second)["previous_report_id"] == first_document["report_id"]


def test_score_class_export_rejects_predecessor_that_appears_before_insert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path, first_epoch, second_epoch = _two_completed_score_epochs(tmp_path)
    earlier = Ledger(path)
    later = Ledger(path)
    predecessor_read = threading.Event()
    allow_later_insert = threading.Event()
    original_lookup = later.previous_score_class_export

    def pause_after_lookup(source_epoch: int, **stream: object):
        prior = original_lookup(source_epoch, **stream)
        assert prior is None
        predecessor_read.set()
        assert allow_later_insert.wait(timeout=5)
        return prior

    monkeypatch.setattr(later, "previous_score_class_export", pause_after_lookup)
    outcome: dict[str, object] = {}

    def export_later() -> None:
        try:
            outcome["report"] = _export_score_class(later, second_epoch)
        except BaseException as exc:  # surfaced deterministically in the main test thread
            outcome["error"] = exc

    thread = threading.Thread(target=export_later)
    thread.start()
    assert predecessor_read.wait(timeout=5)
    try:
        first = _export_score_class(earlier, first_epoch)
    finally:
        allow_later_insert.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert "report" not in outcome
    assert isinstance(outcome.get("error"), ScoreClassError)
    assert "durable export chain changed" in str(outcome["error"])
    monkeypatch.setattr(later, "previous_score_class_export", original_lookup)
    retry = _export_score_class(later, second_epoch)
    assert json.loads(retry)["previous_report_id"] == json.loads(first)["report_id"]
    earlier.close()
    later.close()


def test_score_class_export_rejects_out_of_order_older_epoch(tmp_path: Path):
    path, first_epoch, second_epoch = _two_completed_score_epochs(tmp_path)
    ledger = Ledger(path)

    later = _export_score_class(ledger, second_epoch)
    with pytest.raises(ScoreClassError, match="stale or out of order"):
        _export_score_class(ledger, first_epoch)

    stored = ledger._connection.execute(
        "SELECT source_epoch,report_body FROM score_class_exports"
    ).fetchall()
    assert [(row["source_epoch"], bytes(row["report_body"])) for row in stored] == [(12, later)]
    ledger.close()


def test_score_class_export_rejects_unanchored_explicit_predecessor(tmp_path: Path):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path)

    with pytest.raises(ScoreClassError, match="first score-class export"):
        _export_score_class(
            ledger,
            epoch_id,
            previous_report_id="sha256:" + "f" * 64,
        )
    ledger.close()


def test_concurrent_conflicting_duplicate_export_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "score-class-duplicate.sqlite"
    setup = Ledger(path)
    epoch_id = _completed_zero_epoch(setup, 11)
    setup.close()
    first = Ledger(path)
    second = Ledger(path)
    candidates_ready = threading.Barrier(2)

    def synchronize_lookup(ledger: Ledger) -> None:
        original = ledger.previous_score_class_export

        def lookup(source_epoch: int, **stream: object):
            prior = original(source_epoch, **stream)
            assert prior is None
            candidates_ready.wait(timeout=5)
            return prior

        monkeypatch.setattr(ledger, "previous_score_class_export", lookup)

    synchronize_lookup(first)
    synchronize_lookup(second)
    outcomes: list[bytes | BaseException] = []
    outcome_lock = threading.Lock()

    def export(ledger: Ledger, generated_at: datetime) -> None:
        try:
            outcome: bytes | BaseException = _export_score_class(
                ledger,
                epoch_id,
                generated_at=generated_at,
            )
        except BaseException as exc:  # surfaced deterministically in the main test thread
            outcome = exc
        with outcome_lock:
            outcomes.append(outcome)

    threads = [
        threading.Thread(target=export, args=(first, ISSUED)),
        threading.Thread(target=export, args=(second, ISSUED + timedelta(minutes=1))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    reports = [outcome for outcome in outcomes if isinstance(outcome, bytes)]
    errors = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    assert len(reports) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ScoreClassError)
    assert "conflicting duplicate" in str(errors[0])
    replay_ledger = Ledger(path)
    replay = _export_score_class(replay_ledger, epoch_id)
    assert replay == reports[0]
    replay_ledger.close()
    first.close()
    second.close()


@pytest.mark.parametrize("work_units", [0.30000000000000004, 1e30])
def test_out_of_range_metric_excludes_only_that_miner(tmp_path: Path, work_units: float):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path, work_units=work_units)

    report = json.loads(_export_score_class(ledger, epoch_id))
    rows = {entry["miner_hotkey"]: entry for entry in report["entries"]}

    assert rows["public-hotkey"]["metrics"] == {"verified_work_units": "0"}
    assert rows["public-hotkey"]["reason_codes"] == ["unsupported_work_unit_precision"]
    assert rows["public-hotkey"]["evidence"]
    assert rows["zero-hotkey"]["metrics"] == {"verified_work_units": "0"}


def test_runtime_cli_exports_validator_consumable_score_class(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    ledger, epoch_id = _completed_receipt_epoch(tmp_path)
    ledger.close()
    key_path = tmp_path / "score-class.key"
    key_path.write_bytes(base64.b64encode(RECEIPT_SEED_2))
    key_path.chmod(0o600)
    output = tmp_path / "confidential-compute.json"

    arguments = [
        "runtime",
        "export-score-class",
        "--ledger-db",
        str(tmp_path / "score-class-ledger.sqlite"),
        "--epoch-id",
        str(epoch_id),
        "--score-network",
        "local",
        "--score-netuid",
        "1",
        "--signing-key-id",
        "score-test-1",
        "--signing-key-file",
        str(key_path),
        "--generated-at",
        ISSUED_TEXT,
        "--valid-until",
        "2026-07-17T12:05:00.000000Z",
        "--valid-from-block",
        "70",
        "--valid-until-block",
        "80",
        "--verifier-digest",
        "sha256:" + "d" * 64,
        "--output",
        str(output),
    ]
    assert cli_main(arguments) == 2
    assert "requires --evidence-base-uri" in capsys.readouterr().err
    assert not output.exists()

    result = cli_main([*arguments, "--development"])

    status = json.loads(capsys.readouterr().out)
    report = json.loads(output.read_bytes())
    assert result == 0
    assert status["report_id"] == report["report_id"]
    assert status["entries"] == 2
    assert output.read_bytes() == canonical_json(report)


def test_offline_cli_returns_machine_readable_verification_categories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    snapshot, _policy, _claims_value, receipt = _issued_receipt()
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt.receipt_bytes)
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(canonical_json(_registry_document()))
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps(
            {
                "cathedral-policy-test-1": base64.b64encode(REGISTRY_PUBLIC).decode(
                    "ascii"
                )
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        receipt=str(receipt_path),
        policy_registry=str(registry_path),
        trusted_keys=str(keys_path),
        key_registry=None,
        key_registry_trusted_keys=None,
        key_registry_max_age_seconds=86400,
    )
    assert cmd_receipt_verify(args) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    tampered = json.loads(receipt.receipt_bytes)
    tampered["source_epoch"] = 12
    receipt_path.write_bytes(canonical_json(tampered))
    assert cmd_receipt_verify(args) == 1
    failure = json.loads(capsys.readouterr().out)
    assert failure["valid"] is False
    assert failure["category"] == "schema"

    receipt_path.write_bytes(receipt.receipt_bytes)
    now = datetime.now(UTC)
    generated = now.replace(microsecond=0) - timedelta(hours=2)
    valid_from = generated + timedelta(hours=1)
    valid_until = generated + timedelta(days=1)
    latest = _registry_document(
        release=2,
        receipt_keys=[
            _receipt_key(
                "receipt-test-1",
                RECEIPT_SEED_1,
                status="revoked",
                changed=valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                revoked_at=valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                valid_from=valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                valid_until=valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        ],
    )
    latest.pop("signature")
    latest["generated_at"] = generated.strftime("%Y-%m-%dT%H:%M:%SZ")
    latest["valid_from"] = valid_from.strftime("%Y-%m-%dT%H:%M:%SZ")
    latest["valid_until"] = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    latest["profiles"][0]["status_changed_at"] = latest["valid_from"]
    latest["profiles"][0]["valid_from"] = latest["valid_from"]
    latest["profiles"][0]["valid_until"] = latest["valid_until"]
    latest_path = tmp_path / "latest-registry.json"
    latest_path.write_bytes(canonical_json(sign_registry(latest, REGISTRY_SEED)))
    args.key_registry = str(latest_path)
    assert cmd_receipt_verify(args) == 1
    revoked = json.loads(capsys.readouterr().out)
    assert revoked["valid"] is False
    assert revoked["category"] == "key"
