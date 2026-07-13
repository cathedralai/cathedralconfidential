"""Validator compatibility entrypoint plus hardware-free epoch helpers.

Epoch loop: challenge every miner, verify attestation, gate admission, run the
lanes, score verified work through the routing vector, burn the remainder, set
weights. Sybil defense is free — one attested chip_id backs one UID.
See docs/DESIGN.md §4, §5, §6.

This is the hardware-free *testable core*: the epoch below composes the real
admission contract (verify) + control plane (Inventory) + SAT lane + emission
routing, driven against MOCKED attestation. The MOCK boundary is the only
substitution — everything downstream of an ``Attested`` verdict is the real
Phase-2 code path. Chain submission itself remains scorer-owned in
``cathedralai/cathedral``; this repo's console entrypoint is only a
compatibility wrapper into the existing operator CLI.

Fault isolation in ``attested_epoch``:
  Each miner’s collection + verification phase is wrapped in its own try/except
  so a misbehaving miner (exception in collect_evidence, the verifier, or
  do_sat_work) cannot abort the epoch for its peers. A miner that fails
  admission is simply skipped; one that fails work keeps its attestation floor
  but earns no work score.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from cathedral.api import Inventory
from cathedral.common import Attested, Evidence, Policy, issue_nonce
from cathedral.economics import apply_routing
from cathedral.lanes import ROUTING_VECTOR
from cathedral.lanes.sat import SatLane
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.neuron.miner import MockMiner
from cathedral.verify import verify

# The attestation floor: valid TEE evidence + liveness earns this thin base,
# the remainder is competed for as verified work (docs/DESIGN.md §5).
ATTESTATION_FLOOR = 0.12


@dataclass(frozen=True)
class EpochResult:
    """The outcome of one epoch: emission weights, the burn remainder, and the
    admitted uid set (one per physical chip_id after sybil dedup)."""

    weights: dict[str, float]
    burn: float
    admitted: list[str]


class EvidenceMiner(Protocol):
    """A miner that serves raw attestation evidence and SAT work."""

    uid: str

    def collect_evidence(self, nonce: bytes) -> Evidence: ...

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate: ...


def epoch(
    miners: list[MockMiner],
    policy: Policy,
    *,
    floor: float = ATTESTATION_FLOOR,
    routing: dict[str, float] | None = None,
) -> EpochResult:
    """Run one hardware-free epoch over a set of (mock-attested) miners.

    Steps mirror docs/DESIGN.md §6→§5:
      1. challenge each miner with a fresh nonce; MOCK-verify the served evidence
      2. dedupe by Attested.chip_id — one physical machine backs one UID
      3. register admitted miners; run the SAT lane (dispatch→work→verify→score)
      4. route lane scores through the emission vector; conserve to 1.0

    Phase-1 swap-in: replace ``miner.serve_evidence`` (MOCK) with a real axon
    request and ``verify_mock`` with ``cathedral.verify.verify`` (vendor crypto).
    """

    routing = routing if routing is not None else dict(ROUTING_VECTOR)

    inventory = Inventory()
    lane = SatLane()
    seen_chip: dict[str, str] = {}     # chip_id -> uid (free sybil dedup)
    admitted: list[str] = []
    lane_scores: dict[str, dict[str, float]] = {lane.name: {}}

    for miner in miners:
        # --- admission: challenge -> served evidence -> MOCK-verify ---
        nonce = issue_nonce()
        attested = miner.serve_evidence(nonce, policy)
        if attested is None:
            continue  # invalid quote -> weight 0 -> no emission (DESIGN §8)

        # --- sybil dedup: one physical chip_id backs exactly one UID ---
        if attested.chip_id in seen_chip:
            continue
        seen_chip[attested.chip_id] = miner.uid

        if not lane.qualify(attested):
            continue  # hardware shape does not serve this lane
        inventory.register(miner.uid, attested)
        admitted.append(miner.uid)

        # --- work: dispatch -> miner solves -> certify -> verify -> score ---
        item = lane.dispatch(miner.uid, budget=0)
        cert = miner.do_sat_work(item)
        accepted = lane.verify(item, cert)
        if accepted is None:
            # admitted + live but no verified work this epoch: floor only.
            lane_scores[lane.name][miner.uid] = 0.0
            continue
        lane_scores[lane.name][miner.uid] = lane.score(miner.uid, [accepted])

    # --- emissions: route work through the vector, conserve to 1.0 ---
    weights, burn = apply_routing(lane_scores, routing, floor=floor)
    return EpochResult(weights=weights, burn=burn, admitted=admitted)


def attested_epoch(
    miners: Sequence[EvidenceMiner],
    policy: Policy,
    *,
    floor: float = ATTESTATION_FLOOR,
    routing: dict[str, float] | None = None,
    verifier: Callable[[Evidence, bytes, Policy], Attested | None] = verify,
) -> EpochResult:
    """Run one epoch using real attestation evidence.

    This is the launch-path equivalent of ``epoch``: challenge each miner, ask
    for raw ``Evidence``, vendor-verify it through ``cathedral.verify.verify``,
    admit by physical platform id, run SAT, then route emissions.
    """

    routing = routing if routing is not None else dict(ROUTING_VECTOR)

    inventory = Inventory()
    lane = SatLane()
    seen_chip: dict[str, str] = {}
    admitted: list[str] = []
    lane_scores: dict[str, dict[str, float]] = {lane.name: {}}

    for miner in miners:
        # --- Phase 1: collection + admission (isolated per miner) -----------
        # Any exception here (network, malformed evidence, verifier crash)
        # is caught so a bad miner cannot abort its peers.
        try:
            nonce = issue_nonce()
            evidence = miner.collect_evidence(nonce)
            if evidence.nonce != nonce:
                continue

            attested = verifier(evidence, nonce, policy)
            if attested is None:
                continue

            if attested.chip_id in seen_chip:
                continue
            seen_chip[attested.chip_id] = miner.uid

            if not lane.qualify(attested):
                continue
            inventory.register(miner.uid, attested)
            admitted.append(miner.uid)
        except Exception:  # noqa: BLE001
            continue  # admission failure — skip, do not propagate

        # --- Phase 2: work (isolated per admitted miner) --------------------
        # Admitted miner earns at least the attestation floor; work exceptions
        # leave the work score at 0.0 rather than aborting the epoch.
        lane_scores[lane.name][miner.uid] = 0.0
        try:
            item = lane.dispatch(miner.uid, budget=0)
            cert = miner.do_sat_work(item)
            accepted = lane.verify(item, cert)
            if accepted is not None:
                lane_scores[lane.name][miner.uid] = lane.score(miner.uid, [accepted])
        except Exception:  # noqa: BLE001
            pass  # work failure — miner keeps floor, peers unaffected

    weights, burn = apply_routing(lane_scores, routing, floor=floor)
    return EpochResult(weights=weights, burn=burn, admitted=admitted)


def main(argv: list[str] | None = None) -> int:
    """Compatibility wrapper for ``cathedral runtime ...``.

    This repo intentionally does not own direct Bittensor weight submission.
    Operators invoking ``cathedral-validator`` are forwarded to the existing
    confidential-runtime CLI surface.
    """

    from cathedral import cli as operator_cli

    forwarded = ["runtime", *(sys.argv[1:] if argv is None else argv)]
    return operator_cli.main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
