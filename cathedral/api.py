"""In-process control plane: work queue, inventory, allocator (docs/DESIGN.md §7).

Plain classes, no HTTP server. Customer jobs are FIFO and preempt canonical
backfill; the allocator matches attested capacity against a tier or lane
qualification request.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable

from cathedral.common import Attested, Tier
from cathedral.enroll import RegistryApp, RegistryStore
from cathedral.lanes import WorkItem


class WorkQueue:
    """FIFO customer queue with canonical-work backfill."""

    def __init__(self, backfill: Callable[[], WorkItem]) -> None:
        self._backfill = backfill
        self._jobs: deque[WorkItem] = deque()

    def enqueue(self, item: WorkItem) -> None:
        self._jobs.append(item)

    def claim(self) -> WorkItem:
        if self._jobs:
            return self._jobs.popleft()
        return self._backfill()


class Inventory:
    """Registry of attested miners, keyed by uid."""

    def __init__(self) -> None:
        self._miners: dict[str, Attested] = {}

    def register(self, uid: str, attested: Attested) -> None:
        self._miners[uid] = attested

    def get(self, uid: str) -> Attested | None:
        return self._miners.get(uid)

    def items(self) -> Iterable[tuple[str, Attested]]:
        return self._miners.items()

    def by_tier(self, tier: Tier) -> list[str]:
        return [uid for uid, attested in self._miners.items() if attested.tier == tier]


@dataclass(frozen=True)
class Request:
    """A capacity request: match by lane qualification or by raw tier."""

    tier: Tier | None = None
    lane: object | None = None


class Allocator:
    """Matches requests to attested capacity in an Inventory."""

    def __init__(self, inventory: Inventory) -> None:
        self._inventory = inventory

    def candidates(self, request: Request) -> list[str]:
        if request.lane is not None:
            return [
                uid
                for uid, attested in self._inventory.items()
                if request.lane.qualify(attested)
            ]
        if request.tier is not None:
            return self._inventory.by_tier(request.tier)
        return []

    def allocate(self, request: Request) -> str | None:
        candidates = self.candidates(request)
        return candidates[0] if candidates else None
