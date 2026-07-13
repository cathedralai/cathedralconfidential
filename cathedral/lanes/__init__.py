"""The five-lane verified-work engine (Phase 2).

A miner is attested hardware + lane subscriptions. A lane is a work queue with
four functions; miner weight = Σ over lanes (routing_vector[lane] × lane_score).
See docs/DESIGN.md §4.

Lanes: inference, training, rl, agent_hosting, sat_benchmark.

This module owns only the *interface*. Concrete lanes live in sibling modules
(e.g. cathedral/lanes/sat.py). Concrete work/certificate payloads live in
typed modules (e.g. cathedral/lanes/sat_types.py) and subclass the markers here.
"""

from __future__ import annotations

import abc

from cathedral.common import Attested


class WorkItem:
    """Marker base for a unit of dispatchable work.

    A customer job when the queue has one, else canonical (idle-default) work
    the subnet generates itself. Concrete lanes define concrete subclasses
    (e.g. SatWorkItem).
    """


class Certificate:
    """Marker base for proof a WorkItem was done.

    SAT: a self-certifying assignment / DRAT proof. The enclave-integrity lanes:
    attested measurement + performance probe. Concrete lanes subclass this
    (e.g. SatCertificate).
    """


class Lane(abc.ABC):
    """Every lane implements this. See docs/DESIGN.md §4.

    Subclasses set the class attribute ``name`` (the routing-vector key) and
    implement the four abstract methods. ``dispatch`` prefers paying customer
    work and backfills canonical work when the queue is empty.
    """

    name: str

    @abc.abstractmethod
    def qualify(self, attested: Attested) -> bool:
        """Hardware-shape gate: can this attested miner serve this lane?"""

    @abc.abstractmethod
    def dispatch(self, miner: str, budget: int) -> WorkItem:
        """Customer job if the queue has one, else backfill canonical work."""

    @abc.abstractmethod
    def verify(self, item: WorkItem, result: object) -> Certificate | None:
        """Certificate check (SAT) or attested-measurement + probe. None => fail."""

    @abc.abstractmethod
    def score(self, miner: str, certs: list[Certificate]) -> float:
        """Verified work units -> lane score, fed to the weight-setter."""


# Emission routing across lanes — the "directing compute" control surface,
# tuned per epoch (docs/DESIGN.md §5). Placeholder weights; normalization and
# any unallocated mass are handled by the router.
ROUTING_VECTOR: dict[str, float] = {
    "inference": 0.30,
    "training": 0.20,
    "rl": 0.15,
    "agent_hosting": 0.10,
    "sat_benchmark": 0.25,
}
