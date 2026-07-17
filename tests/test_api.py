"""Contract: the in-process control plane (docs/DESIGN.md §7).

WorkQueue backfills canonical work when no customer job is queued; Allocator
matches requests only to attested capacity whose tier/shape qualifies.
"""

from __future__ import annotations

import pytest

from cathedral.api import Allocator, Inventory, Request, WorkQueue
from cathedral.assurance import attestation_claims
from cathedral.common import Attested, Policy, Tier
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem


def _canonical() -> SatWorkItem:
    inst = SatInstance(n_vars=1, clauses=[[1]])
    return SatWorkItem(
        instance=inst, seed=0, challenge_id=_compute_challenge_id(inst, 0)
    )


def _attested(tier: Tier, chip_id: str) -> Attested:
    policy = Policy(allowed_measurements={"m"})
    return Attested(
        tier,
        chip_id,
        "m",
        3,
        assurance=attestation_claims(chip_id.encode(), policy),
    )


def test_workqueue_backfills_when_empty():
    q = WorkQueue(backfill=_canonical)
    item = q.claim()
    assert isinstance(item, SatWorkItem)
    assert item.seed == 0  # the canonical backfill


def test_workqueue_serves_customer_job_before_backfill():
    q = WorkQueue(backfill=_canonical)
    inst = SatInstance(n_vars=2, clauses=[[1, 2]])
    job = SatWorkItem(instance=inst, seed=7, challenge_id=_compute_challenge_id(inst, 7))
    q.enqueue(job)
    assert q.claim() is job                 # customer job first
    assert q.claim().seed == 0              # then back to canonical backfill


def test_workqueue_is_fifo():
    q = WorkQueue(backfill=_canonical)
    inst_a = SatInstance(1, [[1]])
    inst_b = SatInstance(1, [[1]])
    a = SatWorkItem(instance=inst_a, seed=1, challenge_id=_compute_challenge_id(inst_a, 1))
    b = SatWorkItem(instance=inst_b, seed=2, challenge_id=_compute_challenge_id(inst_b, 2))
    q.enqueue(a)
    q.enqueue(b)
    assert q.claim() is a
    assert q.claim() is b


def test_inventory_registers_and_queries_by_tier():
    inv = Inventory()
    inv.register("uidA", _attested(Tier.CC_CPU_SNP, "c1"))
    inv.register("uidB", _attested(Tier.CC_GPU, "c2"))
    assert inv.by_tier(Tier.CC_CPU_SNP) == ["uidA"]
    assert inv.by_tier(Tier.CC_GPU) == ["uidB"]
    assert inv.get("uidA").chip_id == "c1"


def test_allocator_matches_only_qualifying_tier_for_a_lane():
    inv = Inventory()
    inv.register("uidA", _attested(Tier.CC_CPU_SNP, "c1"))  # qualifies for SAT
    inv.register("uidB", _attested(Tier.CC_GPU, "c2"))  # does not
    alloc = Allocator(inv)
    req = Request(lane=SatLane())
    assert alloc.candidates(req) == ["uidA"]
    assert alloc.allocate(req) == "uidA"


def test_allocator_matches_pod_request_by_tier():
    inv = Inventory()
    inv.register("uidA", _attested(Tier.CC_CPU_SNP, "c1"))
    inv.register("uidB", _attested(Tier.CC_GPU, "c2"))
    alloc = Allocator(inv)
    assert alloc.allocate(Request(tier=Tier.CC_GPU)) == "uidB"


def test_allocator_returns_none_when_nothing_qualifies():
    inv = Inventory()
    inv.register("uidB", _attested(Tier.CC_GPU, "c2"))
    alloc = Allocator(inv)
    assert alloc.allocate(Request(lane=SatLane())) is None


def test_inventory_rejects_legacy_verified_flag_without_typed_claims():
    with pytest.raises(ValueError, match="hardware and software claims"):
        Inventory().register("uid", Attested(Tier.CC_CPU_TDX, "chip", "m", 1))
