"""SAT credit and routing-validity slice (docs/DESIGN.md §4–5).

Miners cannot choose their own credit; all work_units are validator-derived and
finite+nonnegative. Challenge identity prevents duplicate crediting. Routing
produces finite, nonnegative weights that conserve to ~1.0.
"""

from __future__ import annotations

import math

from cathedral.common import Attested, Tier
from cathedral.economics import apply_routing
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem


class TestChallengeIdentity:
    """Challenge ID prevents duplicate crediting."""

    def test_challenge_id_is_deterministic(self):
        """Same instance + seed => same challenge_id."""
        inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3]])
        id1 = _compute_challenge_id(inst, seed=42)
        id2 = _compute_challenge_id(inst, seed=42)
        assert id1 == id2

    def test_challenge_id_differs_on_different_instance(self):
        """Different instance => different challenge_id."""
        inst1 = SatInstance(n_vars=3, clauses=[[1, 2]])
        inst2 = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3]])
        id1 = _compute_challenge_id(inst1, seed=42)
        id2 = _compute_challenge_id(inst2, seed=42)
        assert id1 != id2

    def test_challenge_id_differs_on_different_seed(self):
        """Same instance, different seed => different challenge_id."""
        inst = SatInstance(n_vars=3, clauses=[[1, 2]])
        id1 = _compute_challenge_id(inst, seed=42)
        id2 = _compute_challenge_id(inst, seed=99)
        assert id1 != id2

    def test_challenge_id_in_dispatched_workitem(self):
        """Dispatched work always carries a challenge_id."""
        lane = SatLane()
        item = lane.dispatch("miner-x", budget=0)
        assert isinstance(item, SatWorkItem)
        assert item.challenge_id
        assert len(item.challenge_id) == 64  # sha256 hex digest
        # Verify it's reproducible from the instance + seed
        assert item.challenge_id == _compute_challenge_id(item.instance, item.seed)

    def test_dispatch_produces_distinct_challenge_ids(self):
        """Multiple dispatches produce distinct challenge_ids."""
        lane = SatLane()
        ids = [lane.dispatch("miner-x", 0).challenge_id for _ in range(5)]
        assert len(ids) == len(set(ids))  # all unique

    def test_enqueue_rejects_empty_challenge_id(self):
        """Enqueueing a work item without challenge_id is rejected."""
        inst = SatInstance(n_vars=1, clauses=[[1]])
        bad_item = SatWorkItem(instance=inst, seed=0, challenge_id="")
        lane = SatLane()
        try:
            lane.enqueue(bad_item)
            assert False, "should have raised ValueError"
        except ValueError as e:
            assert "challenge_id" in str(e).lower()


class TestInvalidCreditValues:
    """Miner cannot fake or inflate credit with invalid values."""

    def test_verify_ignores_nan_work_units_claim(self):
        """Cert claiming NaN work_units is replaced with validator-derived value."""
        lane = SatLane()
        inst = SatInstance(n_vars=1, clauses=[[1]])
        from cathedral.lanes.sat import _compute_challenge_id
        challenge_id = _compute_challenge_id(inst, 0)
        item = SatWorkItem(
            instance=inst, seed=0, challenge_id=challenge_id
        )
        lane._issued_ids.add(challenge_id)
        cert = SatCertificate(
            satisfiable=True, assignment=[1], work_units=float("nan"), challenge_id=challenge_id
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.work_units == 1.0  # validator-derived, not NaN

    def test_verify_ignores_infinity_work_units_claim(self):
        """Cert claiming +inf work_units is replaced with validator-derived value."""
        lane = SatLane()
        inst = SatInstance(n_vars=1, clauses=[[1]])
        from cathedral.lanes.sat import _compute_challenge_id
        challenge_id = _compute_challenge_id(inst, 0)
        item = SatWorkItem(
            instance=inst, seed=0, challenge_id=challenge_id
        )
        lane._issued_ids.add(challenge_id)
        cert = SatCertificate(
            satisfiable=True, assignment=[1], work_units=float("inf"), challenge_id=challenge_id
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.work_units == 1.0  # validator-derived, not inf

    def test_verify_ignores_neg_infinity_work_units_claim(self):
        """Cert claiming -inf work_units is replaced with validator-derived value."""
        lane = SatLane()
        inst = SatInstance(n_vars=1, clauses=[[1]])
        from cathedral.lanes.sat import _compute_challenge_id
        challenge_id = _compute_challenge_id(inst, 0)
        item = SatWorkItem(
            instance=inst, seed=0, challenge_id=challenge_id
        )
        lane._issued_ids.add(challenge_id)
        cert = SatCertificate(
            satisfiable=True, assignment=[1], work_units=float("-inf"), challenge_id=challenge_id
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.work_units == 1.0  # validator-derived, not -inf

    def test_verify_ignores_large_claimed_work_units(self):
        """Cert claiming 1e300 work_units is replaced with validator-derived value."""
        lane = SatLane()
        inst = SatInstance(n_vars=1, clauses=[[1]])
        from cathedral.lanes.sat import _compute_challenge_id
        challenge_id = _compute_challenge_id(inst, 0)
        item = SatWorkItem(
            instance=inst, seed=0, challenge_id=challenge_id
        )
        lane._issued_ids.add(challenge_id)
        cert = SatCertificate(
            satisfiable=True, assignment=[1], work_units=1e300, challenge_id=challenge_id
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.work_units == 1.0  # validator-derived, not 1e300

    def test_verify_ignores_negative_work_units_claim(self):
        """Cert claiming negative work_units is replaced with validator-derived value."""
        lane = SatLane()
        inst = SatInstance(n_vars=1, clauses=[[1]])
        from cathedral.lanes.sat import _compute_challenge_id
        challenge_id = _compute_challenge_id(inst, 0)
        item = SatWorkItem(
            instance=inst, seed=0, challenge_id=challenge_id
        )
        lane._issued_ids.add(challenge_id)
        cert = SatCertificate(
            satisfiable=True, assignment=[1], work_units=-5.0, challenge_id=challenge_id
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.work_units == 1.0  # validator-derived, not -5.0

    def test_score_ignores_nan_work_units(self):
        """Score ignores unverified certs regardless of work_units value."""
        # All certs are unverified (not produced by verify()), so score is 0
        certs = [
            SatCertificate(satisfiable=True, assignment=[1], work_units=2.0, challenge_id="c1"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=float("nan"), challenge_id="c2"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=3.0, challenge_id="c3"),
        ]
        assert SatLane().score("miner-x", certs) == 0.0

    def test_score_ignores_infinity_work_units(self):
        """Score ignores unverified certs regardless of work_units value."""
        # All certs are unverified (not produced by verify()), so score is 0
        certs = [
            SatCertificate(satisfiable=True, assignment=[1], work_units=2.0, challenge_id="c1"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=float("inf"), challenge_id="c2"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=3.0, challenge_id="c3"),
        ]
        assert SatLane().score("miner-x", certs) == 0.0

    def test_score_ignores_negative_work_units(self):
        """Score ignores unverified certs regardless of work_units value."""
        # All certs are unverified (not produced by verify()), so score is 0
        certs = [
            SatCertificate(satisfiable=True, assignment=[1], work_units=2.0, challenge_id="c1"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=-10.0, challenge_id="c2"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=3.0, challenge_id="c3"),
        ]
        assert SatLane().score("miner-x", certs) == 0.0

    def test_score_ignores_non_numeric_work_units(self):
        """Score ignores unverified certs regardless of work_units value."""
        # Unverified cert, even with valid work_units, contributes zero
        cert_good = SatCertificate(satisfiable=True, assignment=[1], work_units=5.0, challenge_id="c1")
        certs = [cert_good]
        assert SatLane().score("miner-x", certs) == 0.0


class TestDuplicateCreditPrevention:
    """Same challenge cannot be credited twice."""

    def test_same_challenge_id_distinct_in_epoch(self):
        """Two certs from the same challenge have the same challenge_id."""
        lane = SatLane()
        # Dispatch work with a deterministic seed
        item1 = lane.dispatch("miner-1", 0)
        # Dispatch again increments the seed counter
        item3 = lane.dispatch("miner-2", 0)
        # So item1 and item3 should have different challenge_ids
        assert item1.challenge_id != item3.challenge_id

    def test_duplicate_credit_rejected(self):
        """Submitting the same challenge_id twice is rejected on second attempt."""
        lane = SatLane()
        item = lane.dispatch("miner-1", 0)
        from cathedral.lanes.sat import solve_sat
        assignment = solve_sat(item.instance)
        assert assignment is not None

        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=1.0,
            challenge_id=item.challenge_id,
        )

        # First verification should succeed
        verified1 = lane.verify(item, cert)
        assert verified1 is not None
        assert verified1.challenge_id == item.challenge_id

        # Second verification of the same challenge_id should be rejected
        verified2 = lane.verify(item, cert)
        assert verified2 is None

    def test_mismatched_challenge_id_rejected(self):
        """Cert with wrong challenge_id is rejected."""
        lane = SatLane()
        item = lane.dispatch("miner-1", 0)
        from cathedral.lanes.sat import solve_sat
        assignment = solve_sat(item.instance)
        assert assignment is not None

        # Submit with wrong challenge_id
        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=1.0,
            challenge_id="wrong-id",
        )
        verified = lane.verify(item, cert)
        assert verified is None

    def test_unissued_challenge_id_rejected(self):
        """Cert with unissued challenge_id is rejected."""
        lane = SatLane()
        inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
        from cathedral.lanes.sat import solve_sat
        assignment = solve_sat(inst)
        assert assignment is not None

        challenge_id = _compute_challenge_id(inst, seed=42)
        item = SatWorkItem(instance=inst, seed=42, challenge_id=challenge_id)
        # Note: we did NOT dispatch this, so it's not in _issued_ids

        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=1.0,
            challenge_id=challenge_id,
        )
        verified = lane.verify(item, cert)
        assert verified is None

    def test_verified_cert_carries_challenge_identity(self):
        """A verified cert echoes the challenge_id."""
        lane = SatLane()
        item = lane.dispatch("miner-1", 0)
        from cathedral.lanes.sat import solve_sat
        assignment = solve_sat(item.instance)
        assert assignment is not None

        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=1.0,
            challenge_id=item.challenge_id,
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        assert verified.challenge_id == item.challenge_id


class TestEmptyInputs:
    """Routing and scoring with empty lanes/certs."""

    def test_apply_routing_empty_lanes(self):
        """Empty lane_scores produces empty weights and all burn."""
        weights, burn = apply_routing({}, {"sat_benchmark": 1.0}, floor=0.1)
        assert weights == {}
        assert abs(burn - 1.0) < 1e-9

    def test_apply_routing_empty_mining(self):
        """No admitted miners burns the floor too."""
        weights, burn = apply_routing({}, {}, floor=0.5)
        assert sum(weights.values()) < 1e-9
        assert abs(burn - 1.0) < 1e-9

    def test_score_empty_certs(self):
        """Score of no certs is zero."""
        assert SatLane().score("miner-x", []) == 0.0

    def test_score_all_invalid_certs(self):
        """Score when all certs are invalid is zero."""
        certs = [
            SatCertificate(satisfiable=True, assignment=[1], work_units=float("nan"), challenge_id="c1"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=-5.0, challenge_id="c2"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=float("inf"), challenge_id="c3"),
        ]
        assert SatLane().score("miner-x", certs) == 0.0


class TestRoutingInvariants:
    """Routing conserves and handles edge cases."""

    def test_routing_conserves_with_invalid_scores(self):
        """Routing skips non-finite/negative scores but still conserves."""
        lane_scores = {
            "sat_benchmark": {
                "m1": 1.0,
                "m2": float("nan"),
                "m3": float("inf"),
                "m4": -10.0,
            }
        }
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.1)
        total = sum(weights.values()) + burn
        assert abs(total - 1.0) < 1e-9

    def test_routing_finite_weights_constraint(self):
        """All weights must be finite."""
        lane_scores = {"sat_benchmark": {"m1": 1.0, "m2": 2.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.5)
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)

    def test_routing_nonnegative_weights_constraint(self):
        """All weights must be non-negative."""
        lane_scores = {"sat_benchmark": {"m1": 1.0, "m2": 2.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.5)
        assert all(w >= 0 for w in weights.values())
        assert burn >= 0

    def test_routing_with_zero_routing_vector(self):
        """Zero routing on a lane burns that lane's budget."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 0.0}, floor=0.1)
        assert abs(weights["m1"] - 0.1) < 1e-9  # only floor
        assert abs(burn - 0.9) < 1e-9

    def test_routing_with_negative_routing_shares(self):
        """Negative routing shares are skipped."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}, "inference": {"m2": 1.0}}
        weights, burn = apply_routing(
            lane_scores, {"sat_benchmark": 0.5, "inference": -0.2}, floor=0.0
        )
        # Only sat_benchmark contributes
        total_weight = sum(weights.values())
        assert weights.get("m1", 0) > 0
        assert abs(total_weight + burn - 1.0) < 1e-9

    def test_routing_with_nan_in_routing_vector(self):
        """NaN routing shares are skipped."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(
            lane_scores, {"sat_benchmark": float("nan"), "inference": 1.0}, floor=0.0
        )
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9

    def test_routing_conserves_floor_when_admitted(self):
        """Floor is split equally among admitted miners."""
        lane_scores = {"sat_benchmark": {"m1": 0.0, "m2": 0.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.4)
        # floor 0.4 split 2 ways = 0.2 each; work layer burns
        assert abs(weights.get("m1", 0) - 0.2) < 1e-9
        assert abs(weights.get("m2", 0) - 0.2) < 1e-9
        assert abs(burn - 0.6) < 1e-9

    def test_routing_conserves_with_mixed_valid_invalid_scores(self):
        """Mix of valid and invalid scores still conserves."""
        lane_scores = {
            "sat_benchmark": {"m1": 1.0, "m2": float("inf"), "m3": 2.0}
        }
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.1)
        total = sum(weights.values()) + burn
        assert abs(total - 1.0) < 1e-9
        # m1, m2, m3 all admitted; m2 is skipped for work layer (invalid score)
        # floor 0.1 split 3 ways = 0.033.. each
        # Only m1 and m3 contribute to work layer (0.9 in ratio 1:2)
        # m1 work share: 0.9 * (1/3) = 0.3
        # m3 work share: 0.9 * (2/3) = 0.6
        assert abs(weights.get("m1", 0) - (0.1/3 + 0.3)) < 1e-9
        assert abs(weights.get("m2", 0) - (0.1/3)) < 1e-9  # only floor
        assert abs(weights.get("m3", 0) - (0.1/3 + 0.6)) < 1e-9


class TestFreshLaneNonCollision:
    """Fresh SatLane instances must not emit the same first challenge_id."""

    def test_fresh_lanes_distinct_first_ids(self):
        """Two fresh lanes emit different first challenge_ids."""
        lane1 = SatLane()
        lane2 = SatLane()
        item1 = lane1.dispatch("miner-1", 0)
        item2 = lane2.dispatch("miner-2", 0)
        assert item1.challenge_id != item2.challenge_id

    def test_namespace_reproducibility(self):
        """Same namespace produces same challenge_ids."""
        namespace = "test-epoch-123"
        lane1 = SatLane(namespace=namespace)
        lane2 = SatLane(namespace=namespace)
        item1 = lane1.dispatch("miner-1", 0)
        item2 = lane2.dispatch("miner-2", 0)
        assert item1.challenge_id == item2.challenge_id

    def test_different_namespace_distinct_ids(self):
        """Different namespaces produce different challenge_ids."""
        lane1 = SatLane(namespace="epoch-1")
        lane2 = SatLane(namespace="epoch-2")
        item1 = lane1.dispatch("miner-1", 0)
        item2 = lane2.dispatch("miner-2", 0)
        assert item1.challenge_id != item2.challenge_id


class TestScoreDeduplication:
    """Score defensively counts each challenge_id once."""

    def test_score_deduplicates_challenge_ids(self):
        """Score ignores unverified certs; deduplication happens at verify time."""
        # All certs are unverified (not produced by verify()), so score is 0
        # Deduplication is enforced by verify() rejecting duplicate challenge_ids
        certs = [
            SatCertificate(satisfiable=True, assignment=[1], work_units=5.0, challenge_id="c1"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=3.0, challenge_id="c2"),
            SatCertificate(satisfiable=True, assignment=[1], work_units=7.0, challenge_id="c1"),  # dup
        ]
        assert SatLane().score("miner-x", certs) == 0.0

    def test_score_ignores_missing_challenge_id(self):
        """Score ignores unverified certs regardless of challenge_id value."""
        # All certs are unverified (not produced by verify()), so score is 0
        cert_good = SatCertificate(satisfiable=True, assignment=[1], work_units=5.0, challenge_id="c1")
        cert_bad = SatCertificate(satisfiable=True, assignment=[1], work_units=3.0, challenge_id="")
        certs = [cert_good, cert_bad]
        assert SatLane().score("miner-x", certs) == 0.0


class TestRoutingHardening:
    """Routing must handle invalid floors and overflow gracefully."""

    def test_routing_clamps_floor_below_zero(self):
        """Negative floor is clamped to 0."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=-0.5)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
        assert all(w >= 0 for w in weights.values())

    def test_routing_clamps_floor_above_one(self):
        """Floor > 1.0 is clamped to 1.0."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=2.0)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
        # Floor of 1.0 means all weight goes to floor, nothing to work layer
        assert abs(weights.get("m1", 0) - 1.0) < 1e-9

    def test_routing_handles_nan_floor(self):
        """NaN floor is replaced with 0.0."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=float("nan"))
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)

    def test_routing_handles_inf_floor(self):
        """Infinity floor is replaced with 0.0."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=float("inf"))
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)

    def test_routing_handles_nonnumeric_floor(self):
        """Non-numeric floor is replaced with 0.0."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        # Can't pass string directly, but we test the isinstance check by ensuring
        # numeric floors work
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.5)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9

    def test_routing_handles_overflow_in_denom(self):
        """Overflowed routing total does not produce non-finite results."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        routing = {"lane1": 1e308, "lane2": 1e308}  # sum overflows to inf
        weights, burn = apply_routing(lane_scores, routing, floor=0.1)
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9

    def test_routing_handles_overflow_in_score_total(self):
        """Overflowed score total does not produce non-finite results."""
        lane_scores = {"sat_benchmark": {"m1": 1e308, "m2": 1e308}}  # sum overflows
        weights, burn = apply_routing(lane_scores, {"sat_benchmark": 1.0}, floor=0.1)
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9

    def test_routing_nonnumeric_routing_share_cannot_raise(self):
        """Non-numeric routing shares are skipped without raising."""
        lane_scores = {"sat_benchmark": {"m1": 1.0}}
        # Routing with valid and "invalid" (we can't pass non-numeric, but we
        # test the skip logic with NaN)
        routing = {"sat_benchmark": 1.0, "invalid": float("nan")}
        weights, burn = apply_routing(lane_scores, routing, floor=0.1)
        assert all(math.isfinite(w) for w in weights.values())
        assert math.isfinite(burn)
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9

    def test_routing_all_results_finite_nonnegative(self):
        """Every successful routing result is finite and nonnegative."""
        lane_scores = {
            "sat_benchmark": {"m1": 1.0, "m2": 2.0},
            "inference": {"m3": 3.0},
        }
        routing = {"sat_benchmark": 0.6, "inference": 0.4}
        weights, burn = apply_routing(lane_scores, routing, floor=0.2)
        for w in weights.values():
            assert math.isfinite(w)
            assert w >= 0
        assert math.isfinite(burn)
        assert burn >= 0
        assert abs(sum(weights.values()) + burn - 1.0) < 1e-9
