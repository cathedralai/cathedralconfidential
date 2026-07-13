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


def _v3_payload() -> dict:
    return {
        "burn_snapshot": {"burn_uid": None, "forced_burn_percentage": 0.0},
        "policy_metadata": {"confidential_tdx_cap": {
            "cap_version": "v3",
            "configured_fraction": 0.10,
        }},
        "weights": [
            {
                "miner_hotkey": "base",
                "weight": 0.90,
                "base_component": 0.90,
                "external_component": 0.0,
            },
            {
                "miner_hotkey": "compute",
                "weight": 0.10,
                "base_component": 0.0,
                "external_component": 0.10,
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
    rows = {row["miner_hotkey"]: row for row in payload["weights"]}
    if len(mapping.values()) != len(set(mapping.values())):
        raise ValueError("duplicate UID")
    complete = set(mapping) == set(rows)
    merged: dict[int, float] = {}
    for row in payload["weights"]:
        uid = mapping.get(row["miner_hotkey"])
        if uid is not None:
            value = row["weight"] if complete else row["base_component"]
            if value > 0.0:
                merged[uid] = value
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


def test_survivor_cases_exhaust_proper_nonempty_subsets() -> None:
    cases = gate.survivor_cases(("charlie", "alpha", "bravo"))

    assert len(cases) == 6
    mappings = dict(cases)
    assert mappings["unique:alpha"] == {"alpha": 100}
    assert "unique:alpha+bravo+charlie" not in mappings


def test_quantized_audit_uses_returned_u16_masses() -> None:
    def quantize(uids: list[int], _weights: list[float]) -> tuple[list[int], list[int]]:
        assert uids == [10, 20]
        return uids, [65535, 1000]

    result = gate.audit_quantized_case(
        _exact_ten_percent_payload(),
        {"alpha": 10, "bravo": 20},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )

    expected = gate.CAP
    assert result["total_u16"] == 66535
    assert result["realized_fraction"] == pytest.approx(expected)
    assert result["realized_fraction"] == pytest.approx(gate.CAP, abs=gate.QUANTIZED_FRACTION_TOLERANCE)


def test_quantized_audit_handles_base_only_drop_and_compute_only_row() -> None:
    def quantize(uids: list[int], _weights: list[float]) -> tuple[list[int], list[int]]:
        return uids, [65535]

    dropped = gate.audit_quantized_case(
        _payload(),
        {"alpha": 10},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )
    fallback = gate.audit_quantized_case(
        _v3_payload(),
        {"base": 10},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )

    assert dropped["input_uids"] == 1
    assert dropped["realized_fraction"] == 0.0
    assert fallback["fallback"] is True
    assert fallback["realized_fraction"] == 0.0

    compute_only = gate.audit_quantized_case(
        _v3_payload(),
        {"compute": 12},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )
    assert compute_only["quantized_uids"] == 0
    assert compute_only["realized_fraction"] == 0.0


def test_quantized_audit_full_map_accepts_compute_only_row() -> None:
    def quantize(uids: list[int], _weights: list[float]) -> tuple[list[int], list[int]]:
        return uids, [58982, 6553]

    result = gate.audit_quantized_case(
        _v3_payload(),
        {"base": 10, "compute": 12},
        vector_to_uid_weights=_vector_to_uid_weights,
        quantize=quantize,
    )

    assert result["realized_fraction"] == pytest.approx(gate.CAP, abs=gate.QUANTIZED_FRACTION_TOLERANCE)


def test_signed_component_ratio_allows_compute_only_row_under_global_cap() -> None:
    payload = _v3_payload()

    ratios = gate.signed_component_ratios(payload)

    assert ratios["compute"] == 1.0
    assert gate.signed_confidential_fraction(payload) == pytest.approx(gate.CAP)


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
