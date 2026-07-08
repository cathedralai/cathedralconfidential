"""Contract: emission routing conserves and steers (docs/DESIGN.md §5).

Emissions = attestation floor (per admitted miner) + routing-weighted work layer
+ burn remainder, summing to exactly 1.0.
"""

from __future__ import annotations

from cathedral.economics import apply_routing


def test_emission_conserves_to_one():
    lane_scores = {"sat_benchmark": {"m1": 3.0, "m2": 1.0}}
    routing = {"sat_benchmark": 1.0}
    weights, burn = apply_routing(lane_scores, routing, floor=0.1)
    assert abs(sum(weights.values()) + burn - 1.0) < 1e-9


def test_work_layer_splits_by_score():
    lane_scores = {"sat_benchmark": {"m1": 3.0, "m2": 1.0}}
    routing = {"sat_benchmark": 1.0}
    weights, burn = apply_routing(lane_scores, routing, floor=0.1)
    # floor 0.1 split evenly (0.05 each); work 0.9 split 3:1.
    assert abs(weights["m1"] - (0.05 + 0.675)) < 1e-9
    assert abs(weights["m2"] - (0.05 + 0.225)) < 1e-9
    assert abs(burn) < 1e-9


def test_zero_work_burns_everything_above_floor():
    lane_scores = {"sat_benchmark": {"m1": 0.0, "m2": 0.0}}
    routing = {"sat_benchmark": 1.0}
    weights, burn = apply_routing(lane_scores, routing, floor=0.1)
    # both miners admitted (present with 0 work) -> get floor; work layer burns.
    assert abs(sum(weights.values()) - 0.1) < 1e-9
    assert abs(burn - 0.9) < 1e-9


def test_no_admitted_miners_burns_floor_too():
    weights, burn = apply_routing({}, {"sat_benchmark": 1.0}, floor=0.1)
    assert weights == {} or abs(sum(weights.values())) < 1e-9
    assert abs(burn - 1.0) < 1e-9


def test_routing_steers_allocation():
    lane_scores = {"sat_benchmark": {"m1": 1.0}, "inference": {"m2": 1.0}}
    w_sat, _ = apply_routing(lane_scores, {"sat_benchmark": 0.8, "inference": 0.2}, floor=0.0)
    w_inf, _ = apply_routing(lane_scores, {"sat_benchmark": 0.2, "inference": 0.8}, floor=0.0)
    assert w_sat["m1"] > w_sat["m2"]      # sat-heavy routing favors the sat miner
    assert w_inf["m2"] > w_inf["m1"]      # inference-heavy favors the inference miner
    assert w_sat["m1"] > w_inf["m1"]      # raising sat routing raises the sat miner


def test_routing_normalizes_when_shares_do_not_sum_to_one():
    lane_scores = {"sat_benchmark": {"m1": 1.0}, "inference": {"m2": 1.0}}
    # routing shares sum to 2.0; work layer must still conserve.
    weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0, "inference": 1.0}, floor=0.0)
    assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
    assert abs(weights["m1"] - weights["m2"]) < 1e-9   # equal shares -> equal split
