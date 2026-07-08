"""The five-lane verified-work engine (Phase 2).

A miner is attested hardware + lane subscriptions. A lane is a work queue with
four functions; miner weight = Σ over lanes (routing_vector[lane] × lane_score).
See docs/DESIGN.md §4.

Lanes: inference, training, rl, agent_hosting, sat_benchmark.
"""

from __future__ import annotations

from typing import Protocol

from cathedral.common import Attested


class WorkItem:
    """A unit of dispatchable work (customer job, else canonical/idle-default)."""


class Certificate:
    """Proof a WorkItem was done: SAT assignment / DRAT proof, or attested

    measurement + performance probe for the enclave-integrity lanes.
    """


class Lane(Protocol):
    """Every lane implements this. See docs/DESIGN.md §4."""

    name: str

    def qualify(self, attested: Attested) -> bool:
        """Hardware-shape gate: can this attested miner serve this lane?"""

    def dispatch(self, miner: str, budget: int) -> WorkItem:
        """Customer job if the queue has one, else backfill canonical work."""

    def verify(self, item: WorkItem, result: object) -> Certificate | None:
        """Certificate check (SAT) or attested-measurement + probe. None => fail."""

    def score(self, miner: str, certs: list[Certificate]) -> float:
        """Verified work units -> lane score, fed to the weight-setter."""


# Emission routing across lanes — the "directing compute" control surface,
# tuned per epoch (docs/DESIGN.md §5). Placeholder weights; sum need not be 1
# (the attestation floor + burn take the remainder).
ROUTING_VECTOR: dict[str, float] = {
    "inference": 0.30,
    "training": 0.20,
    "rl": 0.15,
    "agent_hosting": 0.10,
    "sat_benchmark": 0.25,
}
