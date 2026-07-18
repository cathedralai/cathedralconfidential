"""Tests for cathedral.cli: SatWorkItem.challenge_id serialization and legacy queue reload."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import argparse
import importlib

import pytest

from cathedral.cli import (
    DEFAULT_WORKER_BEARER_ENV,
    _build_runtime,
    _dict_to_item,
    _item_to_dict,
    _load_gpu_identity_key,
    _load_policy,
    _load_tokens,
    _outcome_json,
    build_parser,
    cmd_work_prune,
    cmd_work_submit,
    cmd_work_status,
    cmd_worker_serve,
    main,
)
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.gpu import (
    GpuComponentVerdict,
    GpuDeviceClaim,
    GpuIdentityRegistry,
)
from cathedral.ledger import Ledger, LedgerError
from cathedral.runtime import MinerOutcome
from cathedral.worker import WorkerServer


def test_load_policy_supports_strict_tdx_claim_policy(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "allowed_measurements": ["tdx-measurement-1"],
                "min_tcb": 0,
                "tdx_strict": True,
                "tdx_allowed_tcb_statuses": ["UpToDate", "SWHardeningNeeded"],
                "tdx_allowed_advisories": ["INTEL-SA-01234"],
            }
        )
    )

    policy = _load_policy(str(policy_file))

    assert policy.tdx_strict is True
    assert policy.tdx_allowed_tcb_statuses == {"UpToDate", "SWHardeningNeeded"}
    assert policy.tdx_allowed_advisories == {"INTEL-SA-01234"}


@pytest.mark.parametrize(
    "override",
    [
        {"tdx_strict": "true"},
        {"tdx_allowed_tcb_statuses": ["FutureStatus"]},
        {"tdx_allowed_tcb_statuses": ["Revoked"]},
        {"tdx_allowed_advisories": ["bad advisory with spaces"]},
    ],
)
def test_load_policy_rejects_unsafe_tdx_configuration(tmp_path: Path, override):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps({"allowed_measurements": ["m"], "tdx_strict": True, **override})
    )

    with pytest.raises(ValueError):
        _load_policy(str(policy_file))


# ---------------------------------------------------------------------------
# _item_to_dict includes challenge_id
# ---------------------------------------------------------------------------

def test_item_to_dict_includes_challenge_id():
    instance = SatInstance(n_vars=3, clauses=[[1, 2, -3]])
    cid = _compute_challenge_id(instance, 42)
    item = SatWorkItem(instance=instance, seed=42, challenge_id=cid)
    d = _item_to_dict(item)
    assert d["challenge_id"] == cid
    assert d["n_vars"] == 3
    assert d["clauses"] == [[1, 2, -3]]
    assert d["seed"] == 42


# ---------------------------------------------------------------------------
# _dict_to_item with challenge_id present
# ---------------------------------------------------------------------------

def test_dict_to_item_with_challenge_id():
    instance = SatInstance(n_vars=3, clauses=[[1, 2, -3]])
    cid = _compute_challenge_id(instance, 42)
    d = {"n_vars": 3, "clauses": [[1, 2, -3]], "seed": 42, "challenge_id": cid}
    item = _dict_to_item(d)
    assert item.challenge_id == cid
    assert item.instance.n_vars == 3
    assert item.seed == 42


# ---------------------------------------------------------------------------
# _dict_to_item legacy entry (no challenge_id) -> recomputed
# ---------------------------------------------------------------------------

def test_dict_to_item_legacy_no_challenge_id():
    d = {"n_vars": 3, "clauses": [[1, 2, -3]], "seed": 42}
    item = _dict_to_item(d)
    expected_cid = _compute_challenge_id(SatInstance(n_vars=3, clauses=[[1, 2, -3]]), 42)
    assert item.challenge_id == expected_cid


# ---------------------------------------------------------------------------
# _dict_to_item with mismatched challenge_id raises
# ---------------------------------------------------------------------------

def test_dict_to_item_mismatched_challenge_id_raises():
    d = {"n_vars": 3, "clauses": [[1, 2, -3]], "seed": 42, "challenge_id": "bad"}
    with pytest.raises(ValueError, match="does not match"):
        _dict_to_item(d)


# ---------------------------------------------------------------------------
# Round-trip: _item_to_dict -> JSON -> _dict_to_item
# ---------------------------------------------------------------------------

def test_roundtrip_serialization():
    instance = SatInstance(n_vars=5, clauses=[[1, -2, 3], [-4, 5]])
    cid = _compute_challenge_id(instance, 99)
    item = SatWorkItem(instance=instance, seed=99, challenge_id=cid)

    serialized = json.dumps(_item_to_dict(item))
    restored = _dict_to_item(json.loads(serialized))

    assert restored.instance.n_vars == item.instance.n_vars
    assert restored.instance.clauses == item.instance.clauses
    assert restored.seed == item.seed
    assert restored.challenge_id == item.challenge_id


# ---------------------------------------------------------------------------
# CLI work submit writes the job to the runtime ledger
# ---------------------------------------------------------------------------

def test_work_submit_persists_job_in_runtime_ledger(tmp_path: Path, capsys):
    db = tmp_path / "ledger.sqlite"
    args = argparse.Namespace(
        ledger_db=str(db),
        clauses="[[1, -2, 3]]",
        n_vars=3,
        seed=7,
        customer_id="customer-a",
        idempotency_key="customer-request-7",
    )

    rc = cmd_work_submit(args)
    assert rc == 0
    job_id = capsys.readouterr().out.split()[1]
    with Ledger(db) as ledger:
        job = ledger.customer_job(job_id)
    assert job.status == "queued"
    assert job.customer_id == "customer-a"
    assert job.idempotency_key == "customer-request-7"
    expected_cid = _compute_challenge_id(SatInstance(n_vars=3, clauses=[[1, -2, 3]]), 7)
    assert job.item.challenge_id == expected_cid


# ---------------------------------------------------------------------------
# CLI work status reads the runtime ledger
# ---------------------------------------------------------------------------

def test_work_status_empty(tmp_path: Path, capsys):
    args = argparse.Namespace(ledger_db=str(tmp_path / "ledger.sqlite"), job_id=None)
    rc = cmd_work_status(args)
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {
        "customer_jobs": {"failed": 0, "leased": 0, "queued": 0, "succeeded": 0}
    }


def test_work_status_redacts_persisted_failure_details(tmp_path: Path, capsys):
    db = tmp_path / "ledger.sqlite"
    instance = SatInstance(n_vars=1, clauses=[[1]])
    item = SatWorkItem(instance, 1, _compute_challenge_id(instance, 1))
    with Ledger(db) as ledger:
        submitted = ledger.enqueue_customer_job(item)
        lease = ledger.claim_customer_job(
            "worker",
            ledger.begin_epoch(1),
            lease_seconds=60,
            max_attempts=3,
        )
        assert lease is not None
        ledger.resolve_challenge(
            lease.challenge_id,
            "failed",
            customer_lease=lease,
            customer_disposition="failed",
            customer_error="upstream token=customer-secret failed",
        )

    assert cmd_work_status(argparse.Namespace(ledger_db=str(db), job_id=submitted.job_id)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["last_error"] == "upstream token=[REDACTED] failed"


# ---------------------------------------------------------------------------
# CLI parser requires the shared runtime ledger
# ---------------------------------------------------------------------------

def test_work_commands_require_runtime_ledger():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["work", "status"])
    args = parser.parse_args(["work", "status", "--ledger-db", "runtime.sqlite"])
    assert args.ledger_db == "runtime.sqlite"
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "work",
                "submit",
                "--ledger-db",
                "runtime.sqlite",
                "--clauses",
                "[[1]]",
                "--n-vars",
                "1",
            ]
        )
    submitted = parser.parse_args(
        [
            "work",
            "submit",
            "--ledger-db",
            "runtime.sqlite",
            "--customer-id",
            "customer-a",
            "--clauses",
            "[[1]]",
            "--n-vars",
            "1",
        ]
    )
    assert submitted.customer_id == "customer-a"


def test_work_prune_requires_confirmation_and_removes_terminal_history(tmp_path: Path, capsys):
    db = tmp_path / "ledger.sqlite"
    instance = SatInstance(n_vars=1, clauses=[[1]])
    with Ledger(db) as ledger:
        submitted = ledger.enqueue_customer_job(
            SatWorkItem(instance, 1, _compute_challenge_id(instance, 1)),
            customer_id="customer-a",
        )
        lease = ledger.claim_customer_job(
            "worker",
            ledger.begin_epoch(1),
            lease_seconds=60,
            max_attempts=3,
        )
        assert lease is not None
        ledger.resolve_challenge(
            lease.challenge_id,
            "failed",
            customer_lease=lease,
            customer_disposition="failed",
            customer_error="terminal",
        )
    args = argparse.Namespace(
        ledger_db=str(db),
        resolved_before="2999-01-01T00:00:00Z",
        customer_id="customer-a",
        limit=10,
        confirm=False,
    )
    with pytest.raises(ValueError, match="--confirm"):
        cmd_work_prune(args)
    args.confirm = True
    assert cmd_work_prune(args) == 0
    assert json.loads(capsys.readouterr().out) == {"pruned_customer_jobs": 1}
    with Ledger(db) as ledger:
        with pytest.raises(LedgerError, match="not found"):
            ledger.customer_job(submitted.job_id)


# ---------------------------------------------------------------------------
# CLI main: verify-quote subcommand works
# ---------------------------------------------------------------------------

def test_cli_verify_quote_pass():
    rc = main(["verify-quote", "--measurement", "abc", "--allowed-measurement", "abc", "--tcb", "3", "--min-tcb", "1"])
    assert rc == 0


def test_cli_verify_quote_fail():
    rc = main(["verify-quote", "--measurement", "xyz", "--allowed-measurement", "abc", "--tcb", "3", "--min-tcb", "1"])
    assert rc == 1


def test_runtime_run_epoch_is_dry_by_default_and_publish_is_explicit():
    parser = build_parser()
    common = [
        "runtime", "run-epoch",
        "--registry-db", "registry.sqlite",
        "--ledger-db", "ledger.sqlite",
        "--measurements-file", "measurements.json",
        "--canary-hotkey", "canary",
        "--canary-endpoint", "https://8.8.8.8",
        "--source-epoch", "9",
    ]
    assert parser.parse_args(common).publish is False
    assert parser.parse_args([*common, "--publish"]).publish is True


def test_production_run_epoch_requires_explicit_score_audience_before_io():
    args = build_parser().parse_args(
        [
            "runtime",
            "run-epoch",
            "--registry-db",
            "registry.sqlite",
            "--ledger-db",
            "ledger.sqlite",
            "--policy-registry",
            "policy.json",
            "--canary-hotkey",
            "canary",
            "--canary-endpoint",
            "https://8.8.8.8",
            "--source-epoch",
            "9",
        ]
    )
    with pytest.raises(ValueError, match="score reports require"):
        _build_runtime(
            args,
            require_policy=True,
            require_report_audience=True,
        )


def test_runtime_restart_commands_only_require_ledger_path():
    args = build_parser().parse_args(["runtime", "status", "--ledger-db", "ledger.sqlite"])
    assert args.runtime_command == "status"


def test_production_runtime_rejects_legacy_measurements_file(tmp_path: Path):
    measurements = tmp_path / "measurements.json"
    measurements.write_text(json.dumps(["measurement"]))
    args = build_parser().parse_args(
        [
            "runtime",
            "audit-attestation",
            "--registry-db",
            str(tmp_path / "registry.sqlite"),
            "--ledger-db",
            str(tmp_path / "ledger.sqlite"),
            "--measurements-file",
            str(measurements),
            "--canary-hotkey",
            "canary",
            "--canary-endpoint",
            "https://8.8.8.8",
        ]
    )
    with pytest.raises(ValueError, match="development-only"):
        _build_runtime(args, require_policy=True)


def test_gpu_runtime_and_worker_flags_are_explicit_and_complete(tmp_path: Path):
    parser = build_parser()
    worker = parser.parse_args(
        ["worker", "serve", "--hotkey", "worker", "--gpu-composite"]
    )
    assert worker.gpu_composite is True

    runtime = parser.parse_args(
        [
            "runtime",
            "audit-attestation",
            "--registry-db",
            "registry.sqlite",
            "--ledger-db",
            "ledger.sqlite",
            "--policy-registry",
            "policy.json",
            "--gpu-profile-id",
            "tdx-h100-v1",
            "--gpu-identity-db",
            "gpu-identities.sqlite",
            "--gpu-identity-key-file",
            str(tmp_path / "identity.key"),
            "--gpu-identity-anchor-file",
            str(tmp_path / "identity-generation.anchor"),
            "--canary-hotkey",
            "canary",
            "--canary-endpoint",
            "https://8.8.8.8",
        ]
    )
    assert runtime.gpu_profile_id == "tdx-h100-v1"
    assert runtime.gpu_identity_db == "gpu-identities.sqlite"


def test_gpu_audit_json_keeps_component_record_and_stable_failure_category():
    successful = _outcome_json(
        MinerOutcome(
            "worker",
            "https://8.8.8.8",
            "attestation_verified",
            admitted=True,
            component_audit={
                "schema": "cathedral_composite_gpu_audit_v1",
                "cpu": {"status": "verified"},
                "gpu": {"device_count": 2, "status": "verified"},
            },
        )
    )
    failed = _outcome_json(
        MinerOutcome(
            "worker",
            "https://8.8.8.8",
            "attestation_failed",
            error="GPU verifier rejected the component",
            error_category="gpu_component_denied",
        )
    )
    audit_only = _outcome_json(
        MinerOutcome(
            "worker",
            "https://8.8.8.8",
            "attestation_verified",
        )
    )

    assert successful["component_audit"]["gpu"]["device_count"] == 2
    assert successful["verified"] is True
    assert successful["admitted"] is True
    assert audit_only["verified"] is True
    assert audit_only["admitted"] is False
    assert failed["error_category"] == "gpu_component_denied"


def test_gpu_identity_key_file_is_bounded_and_permission_checked(tmp_path: Path):
    key_path = tmp_path / "gpu-identity.key"
    key_path.write_bytes(base64.b64encode(b"i" * 32) + b"\n")
    key_path.chmod(0o600)
    assert _load_gpu_identity_key(str(key_path), production_mode=True) == b"i" * 32

    key_path.chmod(0o644)
    with pytest.raises(ValueError, match="group/world"):
        _load_gpu_identity_key(str(key_path), production_mode=True)


def test_gpu_runtime_configuration_rejects_partial_identity_settings():
    with pytest.raises(ValueError, match="required together"):
        _build_runtime(
            argparse.Namespace(
                gpu_profile_id="tdx-h100-v1",
                gpu_identity_db=None,
                gpu_identity_key_file=None,
            )
        )


def test_recover_gpu_identities_cli_is_authenticated_and_audited(
    tmp_path: Path, capsys
):
    database_parent = tmp_path / "database"
    anchor_parent = tmp_path / "anchor"
    database_parent.mkdir(mode=0o700)
    anchor_parent.mkdir(mode=0o700)
    database = database_parent / "gpu-identities.sqlite"
    anchor = anchor_parent / "generation.anchor"
    key_path = tmp_path / "gpu-identity.key"
    key_path.write_bytes(base64.b64encode(b"i" * 32) + b"\n")
    key_path.chmod(0o600)
    tmp_path.chmod(0o700)
    identity_registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
        initialize=True,
    )
    identity_registry.begin_claim(
        "worker-a",
        GpuComponentVerdict(
            devices=(
                GpuDeviceClaim(
                    "GPU-11111111-1111-4111-8111-111111111111",
                    "NVIDIA-H100-80GB-HBM3",
                    "CC-On",
                    "550.90.07",
                    "96.00.5E.00.01",
                    "Secure",
                    True,
                ),
            ),
            evidence_digest="sha256:" + "1" * 64,
            challenge_digest="sha256:" + "2" * 64,
            host_session_digest="sha256:" + "3" * 64,
            profile_digest="sha256:" + "4" * 64,
            tdx_component_digest="sha256:" + "5" * 64,
            topology_digest=None,
        ),
    )

    assert main(
        [
            "runtime",
            "recover-gpu-identities",
            "--gpu-identity-db",
            str(database),
            "--gpu-identity-key-file",
            str(key_path),
            "--gpu-identity-anchor-file",
            str(anchor),
            "--reason",
            "validator terminated during worker admission",
        ]
    ) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["worker_claims_committed"] == 1
    assert payload["worker_identities_committed"] == 1
    registry = GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
    )
    assert registry.recovery_history()[0]["event_id"] == payload["event_id"]


def test_initialize_gpu_identities_cli_is_explicit_and_one_time(tmp_path: Path, capsys):
    database_parent = tmp_path / "database"
    anchor_parent = tmp_path / "anchor"
    database_parent.mkdir(mode=0o700)
    anchor_parent.mkdir(mode=0o700)
    database = database_parent / "gpu-identities.sqlite"
    anchor = anchor_parent / "generation.anchor"
    key_path = tmp_path / "gpu-identity.key"
    key_path.write_bytes(base64.b64encode(b"i" * 32) + b"\n")
    key_path.chmod(0o600)
    tmp_path.chmod(0o700)
    command = [
        "runtime",
        "initialize-gpu-identities",
        "--gpu-identity-db",
        str(database),
        "--gpu-identity-key-file",
        str(key_path),
        "--gpu-identity-anchor-file",
        str(anchor),
    ]

    assert main(command) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "generation_anchor": str(anchor),
        "identity_database": str(database),
        "initialized": True,
        "production_ready": True,
    }
    assert GpuIdentityRegistry(
        database,
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=anchor,
    ).production_ready

    assert main(command) == 2
    error_payload = json.loads(capsys.readouterr().err)
    assert error_payload == {
        "error": "GPU identity initialization requires unused database and anchor paths"
    }


# ---------------------------------------------------------------------------
# runtime abandon-complete: audited recovery for a stuck 'complete' epoch
# ---------------------------------------------------------------------------


def test_abandon_complete_parser_requires_epoch_id_and_reason():
    parser = build_parser()
    args = parser.parse_args(
        [
            "runtime", "abandon-complete",
            "--ledger-db", "ledger.sqlite",
            "--epoch-id", "3",
            "--reason", "too old for first ingest",
        ]
    )
    assert args.runtime_command == "abandon-complete"
    assert args.epoch_id == 3
    assert args.reason == "too old for first ingest"


@pytest.mark.parametrize(
    "missing",
    [
        ["runtime", "abandon-complete", "--ledger-db", "l.sqlite", "--reason", "x"],
        ["runtime", "abandon-complete", "--ledger-db", "l.sqlite", "--epoch-id", "1"],
    ],
)
def test_abandon_complete_parser_requires_all_flags(missing):
    with pytest.raises(SystemExit):
        build_parser().parse_args(missing)


def test_abandon_complete_end_to_end_unblocks_begin_epoch(tmp_path: Path):
    from cathedral.cli import cmd_runtime_abandon_complete

    db_path = tmp_path / "ledger.sqlite"
    ledger = Ledger(db_path)
    epoch_id = ledger.begin_epoch(1)
    ledger.complete_epoch(epoch_id, set())
    ledger.close()

    args = argparse.Namespace(
        ledger_db=str(db_path),
        epoch_id=epoch_id,
        reason="report too old for first ingest",
    )
    rc = cmd_runtime_abandon_complete(args)
    assert rc == 0

    reopened = Ledger(db_path)
    row = reopened.get_epoch(epoch_id)
    assert row["status"] == "abandoned"
    assert row["abandon_reason"] == "report too old for first ingest"
    assert row["abandoned_at"] is not None
    assert reopened.begin_epoch(2)
    reopened.close()


def test_abandon_complete_prints_epoch_id_reason_and_timestamp(tmp_path: Path, capsys):
    from cathedral.cli import cmd_runtime_abandon_complete

    db_path = tmp_path / "ledger.sqlite"
    ledger = Ledger(db_path)
    epoch_id = ledger.begin_epoch(5)
    ledger.complete_epoch(epoch_id, set())
    ledger.close()

    args = argparse.Namespace(
        ledger_db=str(db_path), epoch_id=epoch_id, reason="stale for ingest"
    )
    assert cmd_runtime_abandon_complete(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["abandoned_epoch_id"] == epoch_id
    assert payload["reason"] == "stale for ingest"
    assert payload["abandoned_at"]


def test_abandon_complete_rejects_running_epoch_via_cli(tmp_path: Path):
    from cathedral.cli import cmd_runtime_abandon_complete

    db_path = tmp_path / "ledger.sqlite"
    ledger = Ledger(db_path)
    epoch_id = ledger.begin_epoch(1)
    ledger.close()

    args = argparse.Namespace(ledger_db=str(db_path), epoch_id=epoch_id, reason="reason")
    with pytest.raises(Exception, match="exact completed"):
        cmd_runtime_abandon_complete(args)


def test_abandon_complete_rejects_empty_reason_via_cli(tmp_path: Path):
    from cathedral.cli import cmd_runtime_abandon_complete

    db_path = tmp_path / "ledger.sqlite"
    ledger = Ledger(db_path)
    epoch_id = ledger.begin_epoch(1)
    ledger.complete_epoch(epoch_id, set())
    ledger.close()

    args = argparse.Namespace(ledger_db=str(db_path), epoch_id=epoch_id, reason="   ")
    with pytest.raises(Exception, match="nonempty"):
        cmd_runtime_abandon_complete(args)


def test_abandon_complete_via_main_reports_error_for_empty_reason(tmp_path: Path, capsys):
    db_path = tmp_path / "ledger.sqlite"
    ledger = Ledger(db_path)
    epoch_id = ledger.begin_epoch(1)
    ledger.complete_epoch(epoch_id, set())
    ledger.close()

    rc = main(
        [
            "runtime", "abandon-complete",
            "--ledger-db", str(db_path),
            "--epoch-id", str(epoch_id),
            "--reason", "   ",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err)
    assert "nonempty" in payload["error"]


def test_worker_serve_defaults_to_loopback():
    args = build_parser().parse_args(["worker", "serve", "--hotkey", "miner"])
    assert args.host == "127.0.0.1"
    assert args.bearer_token_env == DEFAULT_WORKER_BEARER_ENV
    assert args.development_no_auth is False
    assert args.allow_customer_sat is False
    assert args.channel_binding_type is None
    assert args.channel_binding_digest is None


def test_worker_serve_refuses_non_loopback_without_development_flag():
    args = argparse.Namespace(
        host="0.0.0.0",
        port=8081,
        hotkey="miner",
        bearer_token_env=None,
        development_allow_non_loopback=False,
    )
    with pytest.raises(ValueError, match="loopback"):
        cmd_worker_serve(args)


def test_plain_worker_server_itself_guards_non_loopback():
    with pytest.raises(ValueError, match="loopback"):
        WorkerServer("0.0.0.0", configured_hotkey="miner")


def test_worker_serve_requires_default_bearer_environment_value(monkeypatch):
    monkeypatch.delenv(DEFAULT_WORKER_BEARER_ENV, raising=False)
    args = build_parser().parse_args(["worker", "serve", "--hotkey", "miner"])
    with pytest.raises(ValueError, match=DEFAULT_WORKER_BEARER_ENV):
        cmd_worker_serve(args)


def test_worker_production_requires_channel_binding(monkeypatch):
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    args = build_parser().parse_args(["worker", "serve", "--hotkey", "miner"])
    with pytest.raises(ValueError, match="channel binding"):
        cmd_worker_serve(args)


def test_customer_sat_refuses_unauthenticated_worker() -> None:
    args = build_parser().parse_args(
        [
            "worker",
            "serve",
            "--hotkey",
            "miner",
            "--development-no-auth",
            "--allow-customer-sat",
        ]
    )
    with pytest.raises(ValueError, match="bearer authentication and channel binding"):
        cmd_worker_serve(args)


def test_customer_sat_refuses_development_network_bind(monkeypatch) -> None:
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    args = build_parser().parse_args(
        [
            "worker",
            "serve",
            "--hotkey",
            "miner",
            "--allow-customer-sat",
            "--development-allow-non-loopback",
            "--channel-binding-type",
            "application_key_sha256",
            "--channel-binding-digest",
            "ab" * 32,
        ]
    )
    with pytest.raises(ValueError, match="non-loopback"):
        cmd_worker_serve(args)


def test_worker_development_no_auth_is_explicit(monkeypatch):
    calls = []

    class FakeServer:
        host = "127.0.0.1"
        port = 8081

        def __init__(self, *_args, **kwargs):
            calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def serve_forever(self):
            return None

    monkeypatch.setattr("cathedral.cli.WorkerServer", FakeServer)
    args = build_parser().parse_args(
        ["worker", "serve", "--hotkey", "miner", "--development-no-auth"]
    )
    assert cmd_worker_serve(args) == 0
    assert calls[0]["bearer_token"] is None


def test_worker_cli_builds_typed_channel_binding(monkeypatch):
    calls = []

    class FakeServer:
        host = "127.0.0.1"
        port = 8081

        def __init__(self, *_args, **kwargs):
            calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def serve_forever(self):
            return None

    monkeypatch.setattr("cathedral.cli.WorkerServer", FakeServer)
    args = build_parser().parse_args(
        [
            "worker",
            "serve",
            "--hotkey",
            "miner",
            "--development-no-auth",
            "--channel-binding-type",
            "tls_spki_sha256",
            "--channel-binding-digest",
            "ab" * 32,
        ]
    )

    assert cmd_worker_serve(args) == 0
    assert calls[0]["channel_binding"].digest == bytes.fromhex("ab" * 32)


def test_worker_cli_explicitly_enables_authenticated_customer_sat(monkeypatch):
    calls = []

    class FakeServer:
        host = "127.0.0.1"
        port = 8081

        def __init__(self, *_args, **kwargs):
            calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def serve_forever(self):
            return None

    monkeypatch.setattr("cathedral.cli.WorkerServer", FakeServer)
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    args = build_parser().parse_args(
        [
            "worker",
            "serve",
            "--hotkey",
            "miner",
            "--allow-customer-sat",
            "--channel-binding-type",
            "application_key_sha256",
            "--channel-binding-digest",
            "ab" * 32,
        ]
    )

    assert cmd_worker_serve(args) == 0
    assert calls[0]["allow_noncanonical_sat"] is True


def test_production_token_mapping_requires_owner_only_permissions(tmp_path: Path):
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"miner":"secret-token"}', encoding="utf-8")
    token_file.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        _load_tokens(str(token_file), production_mode=True)

    token_file.chmod(0o600)
    assert _load_tokens(str(token_file), production_mode=True) == {
        "miner": "secret-token"
    }

    link = tmp_path / "tokens-link.json"
    link.symlink_to(token_file)
    with pytest.raises(ValueError, match="securely open"):
        _load_tokens(str(link), production_mode=True)


def test_publisher_secrets_have_env_name_flags_only():
    help_text = build_parser().format_help()
    assert "--publisher-bearer-token" not in help_text
    assert "--publisher-hmac-secret" not in help_text


def test_validator_wrapper_forwards_to_runtime(monkeypatch):
    calls = []

    def fake_main(argv):
        calls.append(list(argv))
        return 0

    monkeypatch.setattr("cathedral.cli.main", fake_main)
    validator_mod = importlib.import_module("cathedral.neuron.validator")

    assert validator_mod.main(["status", "--ledger-db", "ledger.sqlite"]) == 0
    assert calls == [["runtime", "status", "--ledger-db", "ledger.sqlite"]]


def test_miner_wrapper_forwards_to_worker(monkeypatch):
    calls = []

    def fake_main(argv):
        calls.append(list(argv))
        return 0

    monkeypatch.setattr("cathedral.cli.main", fake_main)
    miner_mod = importlib.import_module("cathedral.neuron.miner")

    assert miner_mod.main(["serve", "--hotkey", "miner"]) == 0
    assert calls == [["worker", "serve", "--hotkey", "miner"]]


def test_validator_wrapper_help_uses_runtime_parser(capsys):
    validator_mod = importlib.import_module("cathedral.neuron.validator")

    with pytest.raises(SystemExit, match="0"):
        validator_mod.main(["--help"])

    help_text = capsys.readouterr().out
    assert "usage: cathedral runtime" in help_text
    assert "retry-publish" in help_text
    assert "run-epoch" in help_text


def test_miner_wrapper_help_uses_worker_parser(capsys):
    miner_mod = importlib.import_module("cathedral.neuron.miner")

    with pytest.raises(SystemExit, match="0"):
        miner_mod.main(["--help"])

    help_text = capsys.readouterr().out
    assert "usage: cathedral worker" in help_text
    assert "serve" in help_text
