"""The SAT / benchmark lane: a self-certifying verified-work lane (docs/DESIGN.md §4).

Certificate checking is the star: a satisfiable claim is checked by scanning
the instance once (O(#literals), no solving); it cannot be forged because a
wrong assignment simply fails a clause. An UNSAT claim is checked in the
testable core by re-running the DPLL solver below and confirming it also
finds no assignment (Phase-2 replaces this re-solve with a DRAT proof carried
in the certificate).

``solve_sat`` is a small, deterministic DPLL solver: unit propagation, then
branch on the first unassigned variable (try True then False). It is used to
*produce* assignments for canonical work and to check UNSAT claims -- never on
the satisfiable-accept path.
"""

from __future__ import annotations

import random

from cathedral.common import Attested, Tier
from cathedral.lanes import Certificate, Lane, WorkItem
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

_QUALIFIED_TIERS = {Tier.CC_CPU_SNP, Tier.CC_CPU_TDX}


def solve_sat(instance: SatInstance) -> list[int] | None:
    """Deterministic DPLL: unit propagation + first-unassigned-var branching.

    Returns a complete satisfying assignment (unassigned vars default to
    positive/true) or None if the instance is UNSAT.
    """

    assignment: dict[int, bool] = {}

    def unit_propagate(clauses: list[list[int]], assign: dict[int, bool]) -> list[list[int]] | None:
        clauses = list(clauses)
        while True:
            unit = None
            for clause in clauses:
                unresolved = []
                satisfied = False
                for lit in clause:
                    var = abs(lit)
                    if var in assign:
                        if (lit > 0) == assign[var]:
                            satisfied = True
                            break
                    else:
                        unresolved.append(lit)
                if satisfied:
                    continue
                if not unresolved:
                    return None  # empty clause: conflict
                if len(unresolved) == 1:
                    unit = unresolved[0]
                    break
            if unit is None:
                return clauses
            assign[abs(unit)] = unit > 0

    def all_satisfied(clauses: list[list[int]], assign: dict[int, bool]) -> bool:
        for clause in clauses:
            if not any(abs(lit) in assign and (lit > 0) == assign[abs(lit)] for lit in clause):
                return False
        return True

    def backtrack(assign: dict[int, bool]) -> bool:
        remaining = unit_propagate(instance.clauses, assign)
        if remaining is None:
            return False
        if all_satisfied(instance.clauses, assign):
            return True

        unassigned_var = None
        for clause in remaining:
            for lit in clause:
                if abs(lit) not in assign:
                    unassigned_var = abs(lit)
                    break
            if unassigned_var is not None:
                break
        if unassigned_var is None:
            # all variables assigned but not all clauses satisfied (shouldn't
            # happen given unit propagation reached a fixed point) -> conflict
            return False

        for value in (True, False):
            trial = dict(assign)
            trial[unassigned_var] = value
            if backtrack(trial):
                assign.clear()
                assign.update(trial)
                return True
        return False

    if not backtrack(assignment):
        return None

    for var in range(1, instance.n_vars + 1):
        assignment.setdefault(var, True)

    return [var if assignment[var] else -var for var in range(1, instance.n_vars + 1)]


def _canonical_instance(seed: int) -> SatInstance:
    """Deterministically generate a satisfiable-by-construction instance.

    Plant a random assignment from ``seed``, then emit clauses that each
    contain at least one literal true under it -- guaranteeing a certificate
    always exists for canonical (backfill) work.
    """

    rng = random.Random(seed)
    n_vars = 8
    n_clauses = 20
    clause_len = 3

    planted = {v: rng.choice([True, False]) for v in range(1, n_vars + 1)}

    clauses: list[list[int]] = []
    for _ in range(n_clauses):
        vars_in_clause = rng.sample(range(1, n_vars + 1), clause_len)
        true_var = rng.choice(vars_in_clause)
        clause = []
        for v in vars_in_clause:
            if v == true_var:
                lit = v if planted[v] else -v
            else:
                lit = v if rng.choice([True, False]) else -v
            clause.append(lit)
        clauses.append(clause)

    return SatInstance(n_vars=n_vars, clauses=clauses)


class SatLane(Lane):
    """SAT-benchmark lane: dispatches CNF-SAT jobs, verifies self-certifying
    assignments, and re-solves to check UNSAT claims (docs/DESIGN.md §4)."""

    name = "sat_benchmark"

    def __init__(self) -> None:
        self._queue: list[SatWorkItem] = []
        self._seed_counter = 0

    def qualify(self, attested: Attested) -> bool:
        return attested.tier in _QUALIFIED_TIERS

    def enqueue(self, item: SatWorkItem) -> None:
        """Add a customer job to the internal queue (dispatch prefers these)."""

        self._queue.append(item)

    def dispatch(self, miner: str, budget: int) -> WorkItem:
        if self._queue:
            return self._queue.pop(0)

        seed = self._seed_counter
        self._seed_counter += 1
        instance = _canonical_instance(seed)
        return SatWorkItem(instance=instance, seed=seed)

    def verify(self, item: WorkItem, result: object) -> Certificate | None:
        assert isinstance(item, SatWorkItem)
        if not isinstance(result, SatCertificate):
            return None

        instance = item.instance

        if result.satisfiable:
            if result.assignment is None:
                return None
            if len(result.assignment) != instance.n_vars:
                return None
            # Reject inconsistent assignments: every variable 1..n_vars must be
            # assigned exactly once, with a single sign. Without this an
            # adversary could submit a contradictory cert (both +v and -v) that
            # "satisfies" clauses no real Boolean assignment can.
            if {abs(lit) for lit in result.assignment} != set(range(1, instance.n_vars + 1)):
                return None
            true_lits = set(result.assignment)
            for clause in instance.clauses:
                if not any(lit in true_lits for lit in clause):
                    return None
            return result

        # UNSAT claim: testable core re-solves to confirm (Phase-2: DRAT proof).
        if solve_sat(instance) is not None:
            return None
        return result

    def score(self, miner: str, certs: list[Certificate]) -> float:
        return sum(c.work_units for c in certs)  # type: ignore[union-attr]
