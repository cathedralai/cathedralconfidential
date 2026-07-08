"""Emission routing: attestation floor + routing-weighted work + burn (docs/DESIGN.md §5).

Three layers, sum-conserving to exactly 1.0:

1. Floor — `floor` split equally among admitted miners (union of miners across
   all lanes). Burns entirely if there are no admitted miners.
2. Work — `1 - floor` split across lanes by normalized `routing` share, then
   within a lane by score share. A lane with zero total score (or absent from
   `lane_scores`) burns its whole budget.
3. Burn — whatever is left over, i.e. `1.0 - sum(weights.values())`.
"""

from __future__ import annotations


def apply_routing(
    lane_scores: dict[str, dict[str, float]],
    routing: dict[str, float],
    floor: float,
) -> tuple[dict[str, float], float]:
    admitted: set[str] = set()
    for miners in lane_scores.values():
        admitted.update(miners.keys())

    weights: dict[str, float] = {m: 0.0 for m in admitted}

    if admitted:
        share = floor / len(admitted)
        for m in admitted:
            weights[m] += share

    work_total = 1.0 - floor
    denom = sum(routing.values())
    if denom > 0:
        for lane, lane_share in routing.items():
            lane_budget = work_total * lane_share / denom
            miners = lane_scores.get(lane)
            if not miners:
                continue
            total_score = sum(miners.values())
            if total_score <= 0:
                continue
            for m, score in miners.items():
                weights[m] = weights.get(m, 0.0) + lane_budget * score / total_score

    burn = 1.0 - sum(weights.values())
    return weights, burn
