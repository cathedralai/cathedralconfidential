"""Contract: the in-process control plane (docs/DESIGN.md §7).

WorkQueue backfills canonical work when no customer job is queued; Allocator
matches requests only to attested capacity whose tier/shape qualifies.
"""

from __future__ import annotations

from cathedral.api import Allocator, Inventory, Request, WorkQueue
from cathedral.common import Attested, Tier
from cathedral.lanes.sat import SatLane
from cathedral.lanes.sat_types import SatInstance, SatWorkItem


def _canonical() -> SatWorkItem:
    return SatWorkItem(instance=SatInstance(n_vars=1, clauses=[[1]]), seed=0)


def test_workqueue_backfills_when_empty():
    q = WorkQueue(backfill=_canonical)
    item = q.claim()
    assert isinstance(item, SatWorkItem)
    assert item.seed == 0  # the canonical backfill


def test_workqueue_serves_customer_job_before_backfill():
    q = WorkQueue(backfill=_canonical)
    job = SatWorkItem(instance=SatInstance(n_vars=2, clauses=[[1, 2]]), seed=7)
    q.enqueue(job)
    assert q.claim() is job                 # customer job first
    assert q.claim().seed == 0              # then back to canonical backfill


def test_workqueue_is_fifo():
    q = WorkQueue(backfill=_canonical)
    a = SatWorkItem(instance=SatInstance(1, [[1]]), seed=1)
    b = SatWorkItem(instance=SatInstance(1, [[1]]), seed=2)
    q.enqueue(a)
    q.enqueue(b)
    assert q.claim() is a
    assert q.claim() is b


def test_inventory_registers_and_queries_by_tier():
    inv = Inventory()
    inv.register("uidA", Attested(Tier.CC_CPU_SNP, "c1", "m", 3))
    inv.register("uidB", Attested(Tier.CC_GPU, "c2", "m", 3))
    assert inv.by_tier(Tier.CC_CPU_SNP) == ["uidA"]
    assert inv.by_tier(Tier.CC_GPU) == ["uidB"]
    assert inv.get("uidA").chip_id == "c1"


def test_allocator_matches_only_qualifying_tier_for_a_lane():
    inv = Inventory()
    inv.register("uidA", Attested(Tier.CC_CPU_SNP, "c1", "m", 3))  # qualifies for SAT
    inv.register("uidB", Attested(Tier.CC_GPU, "c2", "m", 3))      # does not
    alloc = Allocator(inv)
    req = Request(lane=SatLane())
    assert alloc.candidates(req) == ["uidA"]
    assert alloc.allocate(req) == "uidA"


def test_allocator_matches_pod_request_by_tier():
    inv = Inventory()
    inv.register("uidA", Attested(Tier.CC_CPU_SNP, "c1", "m", 3))
    inv.register("uidB", Attested(Tier.CC_GPU, "c2", "m", 3))
    alloc = Allocator(inv)
    assert alloc.allocate(Request(tier=Tier.CC_GPU)) == "uidB"


def test_allocator_returns_none_when_nothing_qualifies():
    inv = Inventory()
    inv.register("uidB", Attested(Tier.CC_GPU, "c2", "m", 3))
    alloc = Allocator(inv)
    assert alloc.allocate(Request(lane=SatLane())) is None
