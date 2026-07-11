"""Contract: attested_epoch isolates each miner so one failure cannot abort peers.

Covers three fault injection points per miner:
  1. collect_evidence raises       -> miner not admitted, others unaffected
  2. verifier() raises             -> miner not admitted, others unaffected
  3. do_sat_work raises            -> miner admitted (floor) but no work score

Each test pairs a faulty miner with a healthy miner and asserts that the healthy
miner is admitted, receives a positive weight, and the full weight+burn sum
conserves to 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier
from cathedral.lanes.sat import solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.neuron.validator import attested_epoch


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

GOOD_MEASUREMENT = "iso-measurement-1"
GOOD_TCB = 0

_POLICY = Policy(allowed_measurements={GOOD_MEASUREMENT}, min_tcb=GOOD_TCB)
_ROUTING = {"sat_benchmark": 1.0}


@dataclass
class GoodMiner:
    """A cooperative miner that collects evidence and solves SAT work correctly."""

    uid: str
    hotkey: str
    chip_id: str

    def collect_evidence(self, nonce: bytes) -> Evidence:
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=f"quote:{self.uid}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        assignment = solve_sat(item.instance)
        if assignment is None:
            return SatCertificate(satisfiable=False, assignment=None, work_units=1.0)
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
        )


@dataclass
class CollectRaisingMiner:
    """Miner whose collect_evidence always raises."""

    uid: str
    hotkey: str
    chip_id: str

    def collect_evidence(self, nonce: bytes) -> Evidence:
        raise RuntimeError("collect_evidence: simulated failure")

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:  # pragma: no cover
        raise AssertionError("should never be reached")


@dataclass
class WorkRaisingMiner:
    """Miner that collects and verifies fine but raises during do_sat_work."""

    uid: str
    hotkey: str
    chip_id: str

    def collect_evidence(self, nonce: bytes) -> Evidence:
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=f"quote:{self.uid}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        raise RuntimeError("do_sat_work: simulated failure")


# ---------------------------------------------------------------------------
# Verifier: uid-keyed stub
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, str] = {}  # uid -> chip_id


def _verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    """Lightweight verifier stub keyed by uid encoded in the quote bytes."""
    uid = evidence.quote.decode().split(":", 1)[1]
    chip_id = _REGISTRY.get(uid)
    if chip_id is None:
        return None
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=chip_id,
        measurement=GOOD_MEASUREMENT,
        tcb=GOOD_TCB,
    )


def _verifier_raises_for(bad_uid: str):
    """Return a verifier that raises when called for *bad_uid*."""

    def _v(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
        uid = evidence.quote.decode().split(":", 1)[1]
        if uid == bad_uid:
            raise RuntimeError(f"verifier: simulated failure for {uid}")
        chip_id = _REGISTRY.get(uid)
        if chip_id is None:
            return None
        return Attested(
            tier=Tier.CC_CPU_TDX,
            chip_id=chip_id,
            measurement=GOOD_MEASUREMENT,
            tcb=GOOD_TCB,
        )

    return _v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_conserved(result, *, expect_admitted: list[str]) -> None:
    assert result.admitted == expect_admitted, (
        f"admitted mismatch: {result.admitted!r} != {expect_admitted!r}"
    )
    total = sum(result.weights.values()) + result.burn
    assert abs(total - 1.0) < 1e-9, f"weights+burn = {total}"
    for uid in expect_admitted:
        assert result.weights.get(uid, 0) > 0, f"{uid} has zero weight"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_collect_evidence_exception_does_not_abort_peer():
    """collect_evidence raising on miner-A must not prevent miner-B from being admitted."""
    miner_a = CollectRaisingMiner("uid-collect-bad", "hk-a", "chip-a")
    miner_b = GoodMiner("uid-collect-good", "hk-b", "chip-b")

    _REGISTRY.clear()
    _REGISTRY[miner_b.uid] = miner_b.chip_id

    result = attested_epoch(
        [miner_a, miner_b],
        _POLICY,
        routing=_ROUTING,
        verifier=_verifier,
    )

    _assert_conserved(result, expect_admitted=["uid-collect-good"])


def test_verifier_exception_does_not_abort_peer():
    """verifier() raising for miner-A must not prevent miner-B from being admitted."""
    miner_a = GoodMiner("uid-verify-bad", "hk-a", "chip-a")
    miner_b = GoodMiner("uid-verify-good", "hk-b", "chip-b")

    _REGISTRY.clear()
    _REGISTRY[miner_a.uid] = miner_a.chip_id
    _REGISTRY[miner_b.uid] = miner_b.chip_id

    result = attested_epoch(
        [miner_a, miner_b],
        _POLICY,
        routing=_ROUTING,
        verifier=_verifier_raises_for("uid-verify-bad"),
    )

    _assert_conserved(result, expect_admitted=["uid-verify-good"])


def test_do_sat_work_exception_does_not_abort_peer():
    """do_sat_work raising on miner-A must not prevent miner-B from completing work."""
    miner_a = WorkRaisingMiner("uid-work-bad", "hk-a", "chip-a")
    miner_b = GoodMiner("uid-work-good", "hk-b", "chip-b")

    _REGISTRY.clear()
    _REGISTRY[miner_a.uid] = miner_a.chip_id
    _REGISTRY[miner_b.uid] = miner_b.chip_id

    result = attested_epoch(
        [miner_a, miner_b],
        _POLICY,
        routing=_ROUTING,
        verifier=_verifier,
    )

    # Both admitted; miner-a has work failure so only floor, miner-b has work score.
    assert set(result.admitted) == {"uid-work-bad", "uid-work-good"}
    assert result.weights.get("uid-work-good", 0) > result.weights.get("uid-work-bad", 0), (
        "healthy miner should out-earn faulty miner"
    )
    total = sum(result.weights.values()) + result.burn
    assert abs(total - 1.0) < 1e-9


def test_all_miners_faulty_burns_entire_budget():
    """All miners raising at collect must yield no admitted miners and full burn."""
    miners = [
        CollectRaisingMiner(f"uid-all-bad-{i}", f"hk-{i}", f"chip-{i}") for i in range(3)
    ]
    _REGISTRY.clear()

    result = attested_epoch(miners, _POLICY, routing=_ROUTING, verifier=_verifier)

    assert result.admitted == []
    assert result.weights == {}
    assert abs(result.burn - 1.0) < 1e-9


def test_isolated_failures_ordering_does_not_matter():
    """Faulty miner before good miner, then good miner before faulty miner — same result."""
    miner_bad = CollectRaisingMiner("uid-ord-bad", "hk-b", "chip-b")
    miner_good = GoodMiner("uid-ord-good", "hk-g", "chip-g")

    _REGISTRY.clear()
    _REGISTRY[miner_good.uid] = miner_good.chip_id

    result_bad_first = attested_epoch(
        [miner_bad, miner_good], _POLICY, routing=_ROUTING, verifier=_verifier
    )
    result_good_first = attested_epoch(
        [miner_good, miner_bad], _POLICY, routing=_ROUTING, verifier=_verifier
    )

    assert result_bad_first.admitted == ["uid-ord-good"]
    assert result_good_first.admitted == ["uid-ord-good"]
    assert abs(result_bad_first.weights["uid-ord-good"] - result_good_first.weights["uid-ord-good"]) < 1e-9
