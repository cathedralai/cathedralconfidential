#!/usr/bin/env python3
"""Demo: dispatch a SAT instance, solve it, verify the certificate, print PASS.

Hardware-free end-to-end walk of the SAT lane (docs/DESIGN.md §4): the validator
dispatches canonical work, a miner solves it, the miner returns a self-certifying
assignment, and the lane verifies it in microseconds (no re-solving on the
satisfiable-accept path). Run:

    python scripts/demo_sat.py
"""

from __future__ import annotations

from cathedral.lanes.sat import SatLane
from cathedral.neuron.miner import MockMiner


def main() -> int:
    lane = SatLane()
    miner = MockMiner(uid="demo-uid", hotkey="demo-hotkey", chip_id="demo-chip")

    # 1. validator dispatches work (canonical backfill, satisfiable by construction)
    item = lane.dispatch(miner.uid, budget=0)
    print(f"dispatched SAT instance: seed={item.seed} "
          f"n_vars={item.instance.n_vars} n_clauses={len(item.instance.clauses)}")

    # 2. miner solves it and returns a self-certifying certificate
    cert = miner.do_sat_work(item)
    print(f"miner returned: satisfiable={cert.satisfiable} "
          f"assignment={cert.assignment} work_units={cert.work_units}")

    # 3. validator verifies the certificate (µs assignment check, unforgeable)
    accepted = lane.verify(item, cert)
    if accepted is None:
        print("FAIL: certificate rejected")
        return 1

    score = lane.score(miner.uid, [accepted])
    print(f"certificate verified; lane score={score}")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
