"""Contract: one validator epoch, end to end, with mocked attestation.

Composes verify/mock -> api.Inventory -> lanes.sat -> economics into a single
epoch (docs/DESIGN.md §4-6): admit attested miners, run the SAT lane, and route
emissions so weights + burn conserve to ~1.0. No new orchestration module —
the wiring lives here; cathedral/neuron/validator.py stays a Phase-1 stub.
"""

from __future__ import annotations

from cathedral.api import Inventory
from cathedral.common import Policy, issue_nonce
from cathedral.economics import apply_routing
from cathedral.lanes.sat import SatLane, solve_sat
from cathedral.lanes.sat_types import SatCertificate
from cathedral.verify.mock import mock_snp, verify_mock


def test_epoch_admits_runs_sat_and_conserves_weights():
    miners = [("uid-1", "hotkey-1"), ("uid-2", "hotkey-2")]
    inventory = Inventory()
    lane = SatLane()
    lane_scores: dict[str, dict[str, float]] = {lane.name: {}}

    for uid, hotkey in miners:
        # --- admission: challenge -> mock evidence -> verify -> register ---
        nonce = issue_nonce()
        evidence = mock_snp(nonce, hotkey, chip_id=f"chip-{uid}")
        policy = Policy(allowed_measurements={evidence.measurement}, min_tcb=0)
        attested = verify_mock(evidence, nonce, policy)
        assert attested is not None
        assert lane.qualify(attested)
        inventory.register(uid, attested)

        # --- work: dispatch -> solve -> certify -> verify -> score ---
        item = lane.dispatch(uid, budget=0)
        assignment = solve_sat(item.instance)
        assert assignment is not None  # canonical work is SAT by construction
        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
        )
        accepted = lane.verify(item, cert)
        assert accepted is not None
        lane_scores[lane.name][uid] = lane.score(uid, [accepted])

    assert inventory.by_tier(attested.tier)  # miners were admitted

    # --- emissions: route work through the vector, conserve to 1.0 ---
    weights, burn = apply_routing(lane_scores, {lane.name: 1.0}, floor=0.12)
    assert set(weights) == {"uid-1", "uid-2"}
    assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
    assert all(w > 0 for w in weights.values())
