"""Routing-weighted work, an optional compatibility floor, and burn.

Cathedral calls this router with ``floor=0.0``: attestation grants admission,
while only verified work earns weight. The parameter remains to keep the
low-level routing primitive explicit and testable.

Three layers, sum-conserving to exactly 1.0:

1. Optional floor — `floor` split among admitted miners (union across
   all lanes). Burns entirely if there are no admitted miners.
2. Work — `1 - floor` split across lanes by normalized `routing` share, then
   within a lane by score share. A lane with zero total score (or absent from
   `lane_scores`) burns its whole budget.
3. Burn — whatever is left over, i.e. `1.0 - sum(weights.values())`.
"""

from __future__ import annotations

import math


def apply_routing(
    lane_scores: dict[str, dict[str, float]],
    routing: dict[str, float],
    floor: float,
) -> tuple[dict[str, float], float]:
    # Floor must be finite numeric in [0, 1]
    if not isinstance(floor, (int, float)) or not math.isfinite(floor):
        floor = 0.0
    floor = max(0.0, min(1.0, floor))  # clamp to [0, 1]

    admitted: set[str] = set()
    for miners in lane_scores.values():
        admitted.update(miners.keys())

    weights: dict[str, float] = {m: 0.0 for m in admitted}

    if admitted:
        share = floor / len(admitted)
        if not math.isfinite(share) or share < 0:
            share = 0.0
        for m in admitted:
            weights[m] += share

    work_total = 1.0 - floor
    # Guard: only finite, positive routing shares enter the denominator.
    # Nonnumeric routing shares cannot raise.
    denom = 0.0
    for v in routing.values():
        if isinstance(v, (int, float)) and math.isfinite(v) and v > 0:
            denom += v
            # Prevent overflow: if denom becomes non-finite, stop
            if not math.isfinite(denom):
                denom = 0.0
                break

    if denom > 0 and math.isfinite(denom):
        for lane, lane_share in routing.items():
            if not isinstance(lane_share, (int, float)) or not math.isfinite(lane_share) or lane_share <= 0:
                continue
            lane_budget = work_total * lane_share / denom
            if not math.isfinite(lane_budget) or lane_budget < 0:
                continue
            miners = lane_scores.get(lane)
            if not miners:
                continue
            # Guard: only finite, non-negative scores enter the total.
            total_score = 0.0
            for s in miners.values():
                if isinstance(s, (int, float)) and math.isfinite(s) and s >= 0:
                    total_score += s
                    # Prevent overflow
                    if not math.isfinite(total_score):
                        total_score = 0.0
                        break
            if total_score <= 0 or not math.isfinite(total_score):
                continue
            for m, score in miners.items():
                if not isinstance(score, (int, float)) or not math.isfinite(score) or score < 0:
                    continue
                weight_increment = lane_budget * score / total_score
                if not math.isfinite(weight_increment) or weight_increment < 0:
                    continue
                weights[m] = weights.get(m, 0.0) + weight_increment
                # Ensure weight stays finite
                if not math.isfinite(weights[m]):
                    weights[m] = 0.0

    # Ensure all weights are finite and nonnegative
    for m in list(weights.keys()):
        if not math.isfinite(weights[m]) or weights[m] < 0:
            weights[m] = 0.0

    burn = 1.0 - sum(weights.values())
    # Ensure burn is finite and nonnegative
    if not math.isfinite(burn) or burn < 0:
        burn = 0.0

    return weights, burn
