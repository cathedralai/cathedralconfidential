"""Tests for cathedral.cli: SatWorkItem.challenge_id serialization and legacy queue reload."""

from __future__ import annotations

import json
from pathlib import Path

import argparse
import importlib

import pytest

from cathedral.cli import (
    DEFAULT_WORKER_BEARER_ENV,
    _dict_to_item,
    _item_to_dict,
    _load_policy,
    _load_tokens,
    build_parser,
    cmd_work_submit,
    cmd_work_status,
    cmd_worker_serve,
    main,
)
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import Ledger
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
# CLI work submit writes challenge_id to queue file
# ---------------------------------------------------------------------------

def test_work_submit_persists_challenge_id(tmp_path: Path):
    qf = tmp_path / "queue.json"
    args = argparse.Namespace(
        queue_file=str(qf), clauses="[[1, -2, 3]]", n_vars=3, seed=7,
    )

    rc = cmd_work_submit(args)
    assert rc == 0

    data = json.loads(qf.read_text())
    assert len(data) == 1
    assert "challenge_id" in data[0]
    expected_cid = _compute_challenge_id(SatInstance(n_vars=3, clauses=[[1, -2, 3]]), 7)
    assert data[0]["challenge_id"] == expected_cid


# ---------------------------------------------------------------------------
# CLI work status reads queue file
# ---------------------------------------------------------------------------

def test_work_status_empty(tmp_path: Path, capsys):
    args = argparse.Namespace(queue_file=str(tmp_path / "queue.json"))
    rc = cmd_work_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "0" in out


# ---------------------------------------------------------------------------
# Legacy queue reload (file without challenge_id) works
# ---------------------------------------------------------------------------

def test_legacy_queue_reload(tmp_path: Path):
    qf = tmp_path / "queue.json"
    # Write a legacy entry without challenge_id
    legacy = [{"n_vars": 4, "clauses": [[1, -2], [3, 4]], "seed": 10}]
    qf.write_text(json.dumps(legacy))

    args = argparse.Namespace(queue_file=str(qf))
    rc = cmd_work_status(args)
    assert rc == 0


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


def test_runtime_restart_commands_only_require_ledger_path():
    args = build_parser().parse_args(["runtime", "status", "--ledger-db", "ledger.sqlite"])
    assert args.runtime_command == "status"


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
