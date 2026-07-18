"""Signed public policy registry, lifecycle, freshness, and rollback contracts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.policy_registry import (
    MAX_REGISTRY_BYTES,
    PolicyRegistryError,
    PolicyRegistryState,
    canonical_json,
    canonical_signed_bytes,
    parse_registry_json,
    sign_registry,
    verify_registry,
)
from cathedral.cli import (
    _load_registry_keys,
    _verified_registry_policy,
    cmd_policy_registry_verify,
)
from cathedral.ledger import Ledger, LedgerError


PRIVATE_SEED = bytes(range(32))
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
TRUSTED = {"cathedral-policy-test-1": PUBLIC_KEY}
RECEIPT_PRIVATE_SEED = bytes(range(32, 64))
RECEIPT_PUBLIC_KEY = (
    Ed25519PrivateKey.from_private_bytes(RECEIPT_PRIVATE_SEED)
    .public_key()
    .public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
)
NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)


def _profile(
    profile_id: str = "cpu-tdx-sample-v1",
    *,
    status: str = "active",
    status_changed_at: str = "2026-07-17T01:00:00Z",
    valid_from: str = "2026-07-17T01:00:00Z",
    valid_until: str = "2026-07-20T00:00:00Z",
    retire_at: str | None = None,
    measurement: str = "tdx-measurement-sha256:sample-v1",
) -> dict[str, object]:
    return {
        "id": profile_id,
        "kind": "cpu_tdx",
        "status": status,
        "status_changed_at": status_changed_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "retire_at": retire_at,
        "measurements": [measurement],
        "runtime_measurements": ["runtime-sha256:sample-v1"],
        "allowed_firmware": [],
        "min_tcb": 0,
        "tdx_allowed_tcb_statuses": ["UpToDate"],
        "tdx_allowed_advisories": [],
        "metadata": {"description": "Customer-safe sample CPU profile"},
    }


def _unsigned(
    release: int = 1,
    *,
    generated_at: str = "2026-07-17T00:00:00Z",
    valid_from: str = "2026-07-17T01:00:00Z",
    valid_until: str = "2026-07-20T00:00:00Z",
    profiles: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema": "cathedral_policy_registry_v1",
        "release": release,
        "generated_at": generated_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "signing_key_id": "cathedral-policy-test-1",
        "receipt_signing_keys": [
            {
                "id": "cathedral-receipt-test-1",
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(RECEIPT_PUBLIC_KEY).decode("ascii"),
                "purpose": "assurance_receipt",
                "status": "active",
                "status_changed_at": valid_from,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "revoked_at": None,
                "replacement_key_id": None,
                "metadata": {"environment": "test-only"},
            }
        ],
        "profiles": profiles or [_profile(valid_from=valid_from, valid_until=valid_until)],
        "metadata": {"purpose": "public test policy", "critical": True},
    }


def _signed(**kwargs) -> dict[str, object]:
    return sign_registry(_unsigned(**kwargs), PRIVATE_SEED)


def _bytes(document: dict[str, object]) -> bytes:
    return canonical_json(document)


def test_golden_canonicalization_and_ed25519_signature():
    unsigned = _unsigned()
    signed = sign_registry(unsigned, PRIVATE_SEED)

    assert canonical_signed_bytes(signed) == canonical_json(unsigned)
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    snapshot = verify_registry(_bytes(signed), TRUSTED, now=NOW)
    assert snapshot.release == 1
    assert snapshot.signing_key_id == "cathedral-policy-test-1"
    assert snapshot.digest.startswith("sha256:")


def test_production_policy_authority_expires_without_restart():
    snapshot = verify_registry(_bytes(_signed()), TRUSTED, now=NOW)
    policy = snapshot.to_policy(at=NOW, max_age_seconds=86400)

    assert policy.production_ready_at(NOW)
    assert not policy.production_ready_at(NOW + timedelta(hours=13))
    assert not policy.production_ready_at(snapshot.valid_until)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda doc: doc.update(release=2),
        lambda doc: doc.update(generated_at="2026-07-17T00:00:01Z"),
        lambda doc: doc.update(valid_until="2026-07-21T00:00:00Z"),
        lambda doc: doc["profiles"][0]["measurements"].append("other"),
        lambda doc: doc["profiles"][0].update(min_tcb=1),
        lambda doc: doc["receipt_signing_keys"][0].update(status="retired"),
        lambda doc: doc["metadata"].update(critical=False),
    ],
)
def test_every_signed_field_mutation_invalidates_signature(mutation):
    document = _signed()
    mutation(document)
    with pytest.raises(PolicyRegistryError):
        verify_registry(_bytes(document), TRUSTED, now=NOW)


def test_duplicate_keys_unknown_fields_versions_and_profile_ids_fail_closed():
    with pytest.raises(PolicyRegistryError, match="duplicate"):
        parse_registry_json('{"release":1,"release":2}')
    with pytest.raises(PolicyRegistryError, match="valid UTF-8 JSON"):
        parse_registry_json('{"release":' + "9" * 5000 + "}")

    unknown = _signed()
    unknown["future_critical"] = True
    with pytest.raises(PolicyRegistryError):
        verify_registry(_bytes(unknown), TRUSTED, now=NOW)

    version = _signed()
    version["schema"] = "cathedral_policy_registry_v2"
    with pytest.raises(PolicyRegistryError):
        verify_registry(_bytes(version), TRUSTED, now=NOW)

    duplicate = _unsigned(profiles=[_profile(), _profile()])
    with pytest.raises(PolicyRegistryError, match="unique"):
        verify_registry(_bytes(sign_registry(duplicate, PRIVATE_SEED)), TRUSTED, now=NOW)


def test_signature_key_id_algorithm_and_base64_fail_closed():
    with pytest.raises(PolicyRegistryError, match="not trusted"):
        verify_registry(_bytes(_signed()), {}, now=NOW)

    algorithm = _signed()
    algorithm["signature"]["algorithm"] = "hmac"
    with pytest.raises(PolicyRegistryError, match="algorithm"):
        verify_registry(_bytes(algorithm), TRUSTED, now=NOW)

    encoded = _signed()
    encoded["signature"]["value_base64"] = "***"
    with pytest.raises(PolicyRegistryError, match="base64"):
        verify_registry(_bytes(encoded), TRUSTED, now=NOW)


def test_registry_integers_fit_durable_sqlite_representation():
    oversized_release = _unsigned(release=2**63)
    with pytest.raises(PolicyRegistryError, match="bounded positive"):
        verify_registry(_bytes(sign_registry(oversized_release, PRIVATE_SEED)), TRUSTED, now=NOW)

    oversized_tcb = _profile()
    oversized_tcb["min_tcb"] = 2**63
    document = _unsigned(profiles=[oversized_tcb])
    with pytest.raises(PolicyRegistryError, match="bounded nonnegative"):
        verify_registry(_bytes(sign_registry(document, PRIVATE_SEED)), TRUSTED, now=NOW)


def test_admission_freshness_validity_and_clock_boundaries():
    document = _signed()
    assert verify_registry(
        _bytes(document),
        TRUSTED,
        now=datetime(2026, 7, 17, 1, 0, 0, tzinfo=UTC),
    )
    with pytest.raises(PolicyRegistryError, match="validity"):
        verify_registry(
            _bytes(document),
            TRUSTED,
            now=datetime(2026, 7, 20, 0, 0, 0, tzinfo=UTC),
        )

    stale = _signed(
        generated_at="2026-07-14T00:00:00Z",
        valid_from="2026-07-14T01:00:00Z",
        valid_until="2026-07-20T00:00:00Z",
        profiles=[
            _profile(
                status_changed_at="2026-07-14T01:00:00Z",
                valid_from="2026-07-14T01:00:00Z",
                valid_until="2026-07-20T00:00:00Z",
            )
        ],
    )
    with pytest.raises(PolicyRegistryError, match="stale"):
        verify_registry(_bytes(stale), TRUSTED, now=NOW, max_age_seconds=3600)


def test_historical_verification_does_not_make_old_release_current():
    old = _signed(
        generated_at="2026-07-10T00:00:00Z",
        valid_from="2026-07-10T01:00:00Z",
        valid_until="2026-07-12T00:00:00Z",
        profiles=[
            _profile(
                status_changed_at="2026-07-10T01:00:00Z",
                valid_from="2026-07-10T01:00:00Z",
                valid_until="2026-07-12T00:00:00Z",
            )
        ],
    )
    receipt_time = datetime(2026, 7, 11, 0, 0, 0, tzinfo=UTC)
    assert verify_registry(_bytes(old), TRUSTED, now=NOW, historical_at=receipt_time)
    with pytest.raises(PolicyRegistryError):
        verify_registry(_bytes(old), TRUSTED, now=NOW)


def test_active_and_retiring_overlap_then_retired_and_revoked_are_excluded():
    profiles = [
        _profile(
            "old",
            status="retiring",
            status_changed_at="2026-07-17T01:00:00Z",
            retire_at="2026-07-19T00:00:00Z",
            measurement="old-measurement",
        ),
        _profile("new", measurement="new-measurement"),
        _profile(
            "retired",
            status="retired",
            status_changed_at="2026-07-17T02:00:00Z",
            retire_at="2026-07-17T02:00:00Z",
            measurement="retired-measurement",
        ),
        _profile(
            "revoked",
            status="revoked",
            status_changed_at="2026-07-17T02:00:00Z",
            retire_at="2026-07-17T02:00:00Z",
            measurement="revoked-measurement",
        ),
    ]
    snapshot = verify_registry(_bytes(_signed(profiles=profiles)), TRUSTED, now=NOW)
    policy = snapshot.to_policy(at=NOW)

    assert policy.allowed_measurements == {"old-measurement", "new-measurement"}
    assert policy.registry_release == 1
    assert policy.registry_digest == snapshot.digest
    assert policy.registry_profile_ids == ("new", "old")
    after_retirement = snapshot.to_policy(at=datetime(2026, 7, 19, 1, 0, 0, tzinfo=UTC))
    assert after_retirement.allowed_measurements == {"new-measurement"}


def test_overlapping_profiles_cannot_weaken_security_controls():
    weaker = _profile("weaker", measurement="m2")
    weaker["tdx_allowed_tcb_statuses"] = ["UpToDate", "OutOfDate"]
    snapshot = verify_registry(
        _bytes(_signed(profiles=[_profile("strict"), weaker])), TRUSTED, now=NOW
    )
    with pytest.raises(PolicyRegistryError, match="share security"):
        snapshot.to_policy(at=NOW)

    reordered = _profile("reordered", measurement="m3")
    reordered["tdx_allowed_advisories"] = ["INTEL-SA-1", "INTEL-SA-2"]
    original = _profile("original", measurement="m4")
    original["tdx_allowed_advisories"] = ["INTEL-SA-2", "INTEL-SA-1"]
    snapshot = verify_registry(_bytes(_signed(profiles=[original, reordered])), TRUSTED, now=NOW)
    assert snapshot.to_policy(at=NOW).allowed_measurements == {"m3", "m4"}


def test_scheduled_active_profile_is_excluded_until_its_activation_time():
    future = _profile(
        "future",
        status_changed_at="2026-07-18T00:00:00Z",
        valid_from="2026-07-18T00:00:00Z",
        measurement="future-measurement",
    )
    snapshot = verify_registry(
        _bytes(_signed(profiles=[_profile("current"), future])), TRUSTED, now=NOW
    )

    assert snapshot.to_policy(at=NOW).allowed_measurements == {"tdx-measurement-sha256:sample-v1"}
    assert snapshot.to_policy(
        at=datetime(2026, 7, 18, 1, 0, 0, tzinfo=UTC)
    ).allowed_measurements == {
        "tdx-measurement-sha256:sample-v1",
        "future-measurement",
    }


def test_future_non_activation_transition_is_rejected():
    future_retirement = _profile(
        status="retiring",
        status_changed_at="2026-07-18T00:00:00Z",
        retire_at="2026-07-19T00:00:00Z",
    )
    with pytest.raises(PolicyRegistryError, match="not yet effective"):
        verify_registry(_bytes(_signed(profiles=[future_retirement])), TRUSTED, now=NOW)


def test_fresh_production_state_requires_minimum_or_exact_pinned_checkpoint(
    tmp_path: Path,
):
    snapshot = verify_registry(_bytes(_signed()), TRUSTED, now=NOW)
    with pytest.raises(PolicyRegistryError, match="bootstrap"):
        PolicyRegistryState(tmp_path / "empty.sqlite")

    with pytest.raises(PolicyRegistryError, match="pinned checkpoint"):
        PolicyRegistryState(
            tmp_path / "wrong.sqlite",
            pinned_release=1,
            pinned_digest="sha256:" + "0" * 64,
        ).accept(snapshot)

    state = PolicyRegistryState(
        tmp_path / "pinned.sqlite",
        pinned_release=1,
        pinned_digest=snapshot.digest,
    )
    state.accept(snapshot)
    assert state.current()["release"] == 1


def test_rollback_equivocation_and_lost_high_water_mark_fail_closed(tmp_path: Path):
    first = verify_registry(_bytes(_signed(release=1)), TRUSTED, now=NOW)
    second = verify_registry(_bytes(_signed(release=2)), TRUSTED, now=NOW)
    state_path = tmp_path / "state.sqlite"
    state = PolicyRegistryState(state_path, minimum_release=1)
    state.accept(first)
    state.accept(second)
    state.accept(second)  # exact idempotent replay
    with pytest.raises(PolicyRegistryError, match="rollback"):
        state.accept(first)

    equivocated = deepcopy(_unsigned(release=2))
    equivocated["metadata"]["purpose"] = "different signed content"
    equivocation = verify_registry(
        _bytes(sign_registry(equivocated, PRIVATE_SEED)), TRUSTED, now=NOW
    )
    with pytest.raises(PolicyRegistryError, match="equivocated"):
        state.accept(equivocation)

    # A restored/lost state DB still cannot accept below the operator-pinned floor.
    restored = PolicyRegistryState(tmp_path / "restored.sqlite", minimum_release=2)
    with pytest.raises(PolicyRegistryError, match="minimum"):
        restored.accept(first)
    restored.accept(second)


def test_corrupt_persisted_profile_state_fails_closed(tmp_path: Path):
    first = verify_registry(_bytes(_signed(release=1)), TRUSTED, now=NOW)
    second = verify_registry(_bytes(_signed(release=2)), TRUSTED, now=NOW)
    state_path = tmp_path / "state.sqlite"
    state = PolicyRegistryState(state_path, minimum_release=1)
    state.accept(first)
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE policy_registry_state SET profile_states_json = ? WHERE singleton = 1",
            ('{"cpu-tdx-sample-v1":{"status":"unknown","status_changed_at":"bad"}}',),
        )

    with pytest.raises(PolicyRegistryError, match="persisted registry profile state"):
        state.accept(second)


def test_invalid_profile_transitions_and_removal_are_rejected(tmp_path: Path):
    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    first = verify_registry(_bytes(_signed()), TRUSTED, now=NOW)
    state.accept(first)

    retired = _profile(
        status="retired",
        status_changed_at="2026-07-17T02:00:00Z",
        retire_at="2026-07-17T02:00:00Z",
    )
    release2 = verify_registry(_bytes(_signed(release=2, profiles=[retired])), TRUSTED, now=NOW)
    with pytest.raises(PolicyRegistryError, match="transition"):
        state.accept(release2)

    replacement = _profile("replacement")
    removed = verify_registry(_bytes(_signed(release=2, profiles=[replacement])), TRUSTED, now=NOW)
    with pytest.raises(PolicyRegistryError, match="remove"):
        state.accept(removed)


def test_upgrade_simulation_active_to_retiring_to_retired(tmp_path: Path):
    state = PolicyRegistryState(tmp_path / "state.sqlite", minimum_release=1)
    release1 = verify_registry(_bytes(_signed()), TRUSTED, now=NOW)
    state.accept(release1)

    old_retiring = _profile(
        status="retiring",
        status_changed_at="2026-07-17T02:00:00Z",
        retire_at="2026-07-18T00:00:00Z",
    )
    new_active = _profile("cpu-tdx-sample-v2", measurement="new-measurement")
    release2 = verify_registry(
        _bytes(_signed(release=2, profiles=[old_retiring, new_active])),
        TRUSTED,
        now=NOW,
    )
    state.accept(release2)

    old_retired = _profile(
        status="retired",
        status_changed_at="2026-07-18T00:00:00Z",
        retire_at="2026-07-18T00:00:00Z",
    )
    release3 = verify_registry(
        _bytes(_signed(release=3, profiles=[old_retired, new_active])),
        TRUSTED,
        now=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
        max_age_seconds=172800,
    )
    state.accept(release3)

    assert state.current()["release"] == 3


def test_registry_policy_is_immutable_during_epoch_configuration():
    document = _signed()
    snapshot = verify_registry(_bytes(document), TRUSTED, now=NOW)
    policy = snapshot.to_policy(at=NOW)
    document["profiles"][0]["measurements"][0] = "mutated-after-verify"

    assert "mutated-after-verify" not in policy.allowed_measurements
    with pytest.raises(AttributeError):
        policy.allowed_measurements.add("mutation")


def test_registry_metadata_is_deeply_immutable_and_resource_bounded():
    document = _unsigned()
    document["metadata"] = {"nested": {"values": ["one", "two"]}}
    snapshot = verify_registry(_bytes(sign_registry(document, PRIVATE_SEED)), TRUSTED, now=NOW)
    with pytest.raises(TypeError):
        snapshot.metadata["nested"]["new"] = True
    with pytest.raises(AttributeError):
        snapshot.metadata["nested"]["values"].append("three")

    with pytest.raises(PolicyRegistryError, match="maximum encoded size"):
        parse_registry_json(b" " * (MAX_REGISTRY_BYTES + 1))

    too_deep: dict[str, object] = {}
    cursor = too_deep
    for _ in range(40):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    document = _unsigned()
    document["metadata"] = too_deep
    with pytest.raises(PolicyRegistryError, match="deeply nested"):
        verify_registry(_bytes(sign_registry(document, PRIVATE_SEED)), TRUSTED, now=NOW)


def test_runtime_registry_path_verifies_before_advancing_checkpoint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    clock = datetime.now(UTC).replace(microsecond=0)
    generated = (clock - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_from = (clock - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = (clock + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    profile = _profile(
        status_changed_at=valid_from,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    document = _signed(
        generated_at=generated,
        valid_from=valid_from,
        valid_until=valid_until,
        profiles=[profile],
    )
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(_bytes(document))
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({"cathedral-policy-test-1": base64.b64encode(PUBLIC_KEY).decode("ascii")}),
        encoding="utf-8",
    )
    state_path = tmp_path / "state.sqlite"
    keys_digest = "sha256:" + hashlib.sha256(keys_path.read_bytes()).hexdigest()

    policy = _verified_registry_policy(
        str(registry_path),
        str(keys_path),
        state_path=str(state_path),
        minimum_release=1,
        max_age_seconds=3600,
        production_mode=True,
        trusted_keys_digest=keys_digest,
    )
    assert policy.registry_release == 1
    assert PolicyRegistryState(state_path, minimum_release=1).current()["release"] == 1

    pinned_state = tmp_path / "pinned-state.sqlite"
    pinned_policy = _verified_registry_policy(
        str(registry_path),
        str(keys_path),
        state_path=str(pinned_state),
        minimum_release=None,
        max_age_seconds=3600,
        production_mode=True,
        trusted_keys_digest=keys_digest,
        pinned_release=1,
        pinned_digest=policy.registry_digest,
    )
    assert pinned_policy.registry_digest == policy.registry_digest

    args = argparse.Namespace(
        registry=str(registry_path),
        trusted_keys=str(keys_path),
        max_age_seconds=3600,
    )
    assert cmd_policy_registry_verify(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["release"] == 1
    assert output["profiles"] == [
        {"id": "cpu-tdx-sample-v1", "kind": "cpu_tdx", "status": "active"}
    ]

    gpu = deepcopy(profile)
    gpu.update(
        id="gpu-sample",
        kind="gpu_cc",
        measurements=[],
        tdx_allowed_tcb_statuses=[],
    )
    unusable = _signed(
        release=2,
        generated_at=generated,
        valid_from=valid_from,
        valid_until=valid_until,
        profiles=[gpu],
    )
    unusable_path = tmp_path / "unusable.json"
    unusable_path.write_bytes(_bytes(unusable))
    untouched_state = tmp_path / "unusable-state.sqlite"
    with pytest.raises(PolicyRegistryError, match="no eligible CPU TDX"):
        _verified_registry_policy(
            str(unusable_path),
            str(keys_path),
            state_path=str(untouched_state),
            minimum_release=1,
            max_age_seconds=3600,
            production_mode=True,
            trusted_keys_digest=keys_digest,
        )
    assert not untouched_state.exists()


def test_production_trusted_keys_require_independent_digest(tmp_path: Path):
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({"cathedral-policy-test-1": base64.b64encode(PUBLIC_KEY).decode("ascii")}),
        encoding="utf-8",
    )
    digest = "sha256:" + hashlib.sha256(keys_path.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="require a pinned digest"):
        _load_registry_keys(str(keys_path), production_mode=True)
    assert _load_registry_keys(str(keys_path), production_mode=True, pinned_digest=digest) == {
        "cathedral-policy-test-1": PUBLIC_KEY
    }

    keys_path.write_text(keys_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        _load_registry_keys(str(keys_path), production_mode=True, pinned_digest=digest)


def test_epoch_report_commits_to_registry_release_and_digest(tmp_path: Path):
    snapshot = verify_registry(_bytes(_signed()), TRUSTED, now=NOW)
    ledger = Ledger(tmp_path / "ledger.sqlite")
    epoch_id = ledger.begin_epoch(
        7,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    ledger.complete_epoch(epoch_id, [])
    report = json.loads(ledger.report_bytes(epoch_id))

    assert report["metadata"]["policy_registry_release"] == 1
    assert report["metadata"]["policy_registry_digest"] == snapshot.digest

    with pytest.raises(LedgerError, match="registry metadata"):
        ledger.begin_epoch(
            8,
            policy_registry_release=2**63,
            policy_registry_digest=snapshot.digest,
        )


def test_existing_ledger_schema_migrates_registry_audit_fields(tmp_path: Path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE epochs (
                epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_epoch INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                published_at TEXT,
                generated_at TEXT,
                report_body BLOB,
                report_digest TEXT,
                abandoned_at TEXT,
                abandon_reason TEXT
            )
            """
        )
    ledger = Ledger(path)
    columns = {row["name"] for row in ledger._connection.execute("PRAGMA table_info(epochs)")}

    assert "policy_registry_release" in columns
    assert "policy_registry_digest" in columns


def test_sample_registry_and_public_key_verify():
    base = Path("examples/policy-registry")
    keys = json.loads((base / "trusted-keys.json").read_text(encoding="utf-8"))
    trusted = {key_id: base64.b64decode(value, validate=True) for key_id, value in keys.items()}
    snapshot = verify_registry((base / "registry-v1.json").read_bytes(), trusted, now=NOW)

    assert snapshot.release == 1
    assert snapshot.to_policy(at=NOW).registry_digest == snapshot.digest


def test_documented_historical_sample_cli_remains_verifiable(
    capsys: pytest.CaptureFixture[str],
):
    base = Path("examples/policy-registry")
    args = argparse.Namespace(
        registry=str(base / "registry-v1.json"),
        trusted_keys=str(base / "trusted-keys.json"),
        max_age_seconds=86400,
        historical_at="2026-07-17T12:00:00Z",
    )

    assert cmd_policy_registry_verify(args) == 0
    assert json.loads(capsys.readouterr().out)["release"] == 1

    args.historical_at = "2026-7-17T12:00:00Z"
    with pytest.raises(ValueError, match="canonical UTC"):
        cmd_policy_registry_verify(args)
