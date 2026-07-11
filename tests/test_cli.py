"""Tests for cathedral.cli: SatWorkItem.challenge_id serialization and legacy queue reload."""

from __future__ import annotations

import json
from pathlib import Path

import argparse

import pytest

from cathedral.cli import _dict_to_item, _item_to_dict, cmd_work_submit, cmd_work_status, main
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem


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
