from __future__ import annotations

import json
from pathlib import Path

import pytest

from cathedral.ledger import Ledger
from scripts import cross_repo_launch_verify as gate


def _payload() -> dict:
    return {
        "burn_snapshot": {"burn_uid": None, "forced_burn_percentage": 0.0},
        "weights": [
            {
                "miner_hotkey": "alpha",
                "weight": 0.55,
                "base_component": 0.50,
                "external_component": 0.05,
            },
            {
                "miner_hotkey": "bravo",
                "weight": 0.45,
                "base_component": 0.42,
                "external_component": 0.03,
            },
        ],
    }


def _exact_ten_percent_payload() -> dict:
    return {
        "burn_snapshot": {"burn_uid": None, "forced_burn_percentage": 0.0},
        "weights": [
            {
                "miner_hotkey": "alpha",
                "weight": 0.60,
                "base_component": 0.54,
                "external_component": 0.06,
            },
            {
                "miner_hotkey": "bravo",
                "weight": 0.40,
                "base_component": 0.36,
                "external_component": 0.04,
            },
        ],
    }


def _vector_to_uid_weights(payload: dict, mapping: dict[str, int]) -> dict[int, float]:
    merged: dict[int, float] = {}
    for row in payload["weights"]:
        uid = mapping.get(row["miner_hotkey"])
        if uid is not None:
            merged[uid] = merged.get(uid, 0.0) + row["weight"]
    total = sum(merged.values())
    return {uid: value / total for uid, value in merged.items()}


def test_ledger_helpers_freeze_positive_then_complete_zero(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite")
    positive_epoch, positive = gate.create_positive_epoch(
        ledger,
        generated_at="2026-07-11T12:00:00Z",
    )
    ledger.mark_published(positive_epoch)
    zero_epoch, zero = gate.create_zero_epoch(
        ledger,
        generated_at="2026-07-11T12:01:00Z",
    )

    positive_report = json.loads(ledger.report_bytes(positive_epoch))
    zero_report = json.loads(ledger.report_bytes(zero_epoch))
    assert positive[gate.CONFIDENTIAL_ONLY] > 0.0
    assert positive_report["complete"] is True
    assert zero_report["complete"] is True
    assert set(zero) == set(gate.ALL_HOTKEYS)
    assert set(row["score"] for row in zero_report["scores"]) == {0.0}


def test_survivor_cases_exhaust_subsets_and_include_uid_merges() -> None:
    cases = gate.survivor_cases(("charlie", "alpha", "bravo"))

    assert len(cases) == 11
    mappings = dict(cases)
    assert mappings["unique:alpha"] == {"alpha": 100}
    assert mappings["unique:alpha+bravo+charlie"] == {
        "alpha": 100,
        "bravo": 101,
        "charlie": 102,
    }
    assert set(mappings["merged:alpha+bravo+charlie"].values()) == {900}


def test_quantized_audit_uses_returned_u16_masses() -> None:
    def quantize(uids: list[int], _weights: list[float]) -> tuple[list[int], list[int]]:
        assert uids == [10, 20]
        return uids, [65535, 1000]

    result = gate.audit_quantized_case(
        _payload(),
        {"alpha": 10, "bravo": 20},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )

    alpha_ratio = 0.05 / 0.55
    bravo_ratio = 0.03 / 0.45
    expected = (65535 * alpha_ratio + 1000 * bravo_ratio) / 66535
    assert result["total_u16"] == 66535
    assert result["realized_fraction"] == pytest.approx(expected)
    assert result["realized_fraction"] < gate.CAP


def test_quantized_audit_handles_drop_and_duplicate_uid_merge() -> None:
    def quantize(uids: list[int], _weights: list[float]) -> tuple[list[int], list[int]]:
        return uids, [65535]

    dropped = gate.audit_quantized_case(
        _payload(),
        {"alpha": 10},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )
    merged = gate.audit_quantized_case(
        _payload(),
        {"alpha": 10, "bravo": 10},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )

    assert dropped["input_uids"] == 1
    assert dropped["realized_fraction"] == pytest.approx(0.05 / 0.55)
    assert merged["input_uids"] == 1
    assert merged["realized_fraction"] == pytest.approx(0.08)


def test_signed_component_ratio_over_cap_fails_closed() -> None:
    payload = _payload()
    payload["weights"][0] = {
        "miner_hotkey": "alpha",
        "weight": 1.0,
        "base_component": 0.89,
        "external_component": 0.11,
    }

    with pytest.raises(gate.LaunchProofError, match="exceeds 10%"):
        gate.signed_component_ratios(payload)


def test_signed_confidential_fraction_requires_exact_10_percent() -> None:
    fraction = gate.signed_confidential_fraction(_exact_ten_percent_payload())

    assert fraction == pytest.approx(gate.CAP)


def test_signed_confidential_fraction_fails_when_external_mass_drops_to_zero() -> None:
    payload = _payload()
    for row in payload["weights"]:
        row["weight"] = row["base_component"]
        row["external_component"] = 0.0

    with pytest.raises(gate.LaunchProofError, match="zero confidential attribution"):
        gate.signed_confidential_fraction(payload)


def test_signed_confidential_fraction_fails_on_sub_ten_percent_positive_mass() -> None:
    payload = _payload()
    payload["weights"] = [
        {
            "miner_hotkey": "alpha",
            "weight": 0.56,
            "base_component": 0.50,
            "external_component": 0.06,
        },
        {
            "miner_hotkey": "bravo",
            "weight": 0.44,
            "base_component": 0.42,
            "external_component": 0.02,
        },
    ]

    with pytest.raises(gate.LaunchProofError, match="does not match the 10% target"):
        gate.signed_confidential_fraction(payload)


def test_temporary_environment_restores_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_PROOF_EXISTING", "before")
    monkeypatch.setenv("CATHEDRAL_PROOF_REMOVED", "remove-me")

    with gate.temporary_environment(
        {"CATHEDRAL_PROOF_EXISTING": "during", "CATHEDRAL_PROOF_REMOVED": None}
    ):
        assert gate.os.environ["CATHEDRAL_PROOF_EXISTING"] == "during"
        assert "CATHEDRAL_PROOF_REMOVED" not in gate.os.environ

    assert gate.os.environ["CATHEDRAL_PROOF_EXISTING"] == "before"
    assert gate.os.environ["CATHEDRAL_PROOF_REMOVED"] == "remove-me"


def test_scorer_environment_forces_local_isolation() -> None:
    environment = gate.scorer_environment()

    assert environment["DATABASE_URL"] is None
    assert environment["CATHEDRAL_V2_DATABASE_URL"] is None
    assert environment["CATHEDRAL_HIPPIUS_TOKEN"] is None
    assert environment["CATHEDRAL_RATELIMIT_RPM"] == "0"
