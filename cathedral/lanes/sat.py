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

import hashlib
import hmac
import json
import math
import random

from cathedral.common import Attested, Tier
from cathedral.lanes import Certificate, Lane, WorkItem
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

_QUALIFIED_TIERS = {Tier.CC_CPU_SNP, Tier.CC_CPU_TDX}
_MAX_NONNEGATIVE_SIGNED_I64 = (1 << 63) - 1


def _compute_challenge_id(instance: SatInstance, seed: int) -> str:
    """Deterministic hash of instance + seed to prevent duplicate crediting.

    Returns the hex digest of sha256(json(instance) + seed). This challenge_id
    is immutable after dispatch — it cannot be forged or duplicated.
    """
    payload = {
        "n_vars": instance.n_vars,
        "clauses": instance.clauses,
        "seed": seed,
    }
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode())
    return h.hexdigest()


def _derive_canonical_seed(namespace: str, counter: int) -> int:
    """Derive a reproducible canonical SAT seed from namespace + counter.

    Uses the first 64 HMAC bits and masks to the nonnegative signed-64-bit
    range already accepted by the remote worker protocol. Retaining these high
    bits avoids collapsing the seed space to 31 bits, which would sharply raise
    challenge-id collision risk once ledger challenge IDs are globally unique.
    """

    seed_bytes = hmac.new(
        namespace.encode(),
        str(counter).encode(),
        hashlib.sha256,
    ).digest()
    return int.from_bytes(seed_bytes[:8], "big") & _MAX_NONNEGATIVE_SIGNED_I64


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

    def __init__(self, namespace: str | None = None) -> None:
        self._queue: list[SatWorkItem] = []
        # Fresh instances should not emit the same first ID. Use a random
        # namespace to prevent collision across epochs while keeping the SAT
        # instance reproducible from (namespace, counter).
        self._namespace = namespace or hashlib.sha256(random.randbytes(16)).hexdigest()[:8]
        self._seed_counter = 0
        self._issued_ids: set[str] = set()
        # Map challenge_id -> owner miner (tracked at dispatch time).
        self._challenge_owner: dict[str, str] = {}
        # Map challenge_id -> work_units for verified certificates only.
        # This ensures score() only counts certs that passed verify().
        self._verified_credits: dict[str, float] = {}

    def qualify(self, attested: Attested) -> bool:
        return attested.tier in _QUALIFIED_TIERS

    def enqueue(self, item: SatWorkItem) -> None:
        """Add a customer job to the internal queue (dispatch prefers these).

        The item must have a valid challenge_id matching _compute_challenge_id(
        instance, seed). This prevents duplicate crediting and internal consistency
        errors across epochs.
        """
        if not item.challenge_id:
            raise ValueError("enqueue: item.challenge_id must be non-empty")
        computed_id = _compute_challenge_id(item.instance, item.seed)
        if item.challenge_id != computed_id:
            raise ValueError(
                f"enqueue: challenge_id mismatch: provided {item.challenge_id}, "
                f"computed {computed_id} from instance + seed"
            )
        self._queue.append(item)

    def dispatch(self, miner: str, budget: int) -> WorkItem:
        if self._queue:
            item = self._queue.pop(0)
            self._issued_ids.add(item.challenge_id)
            self._challenge_owner[item.challenge_id] = miner
            return item

        # Derive seed from namespace + counter using stable HMAC, not Python
        # hash() which is process-salted and not reproducible. HMAC-SHA256
        # ensures identical namespace/counter always yields identical seed
        # across different PYTHONHASHSEED values.
        seed = _derive_canonical_seed(self._namespace, self._seed_counter)
        self._seed_counter += 1
        instance = _canonical_instance(seed)
        challenge_id = _compute_challenge_id(instance, seed)
        self._issued_ids.add(challenge_id)
        self._challenge_owner[challenge_id] = miner
        return SatWorkItem(instance=instance, seed=seed, challenge_id=challenge_id)

    def verify(self, item: WorkItem, result: object) -> Certificate | None:
        assert isinstance(item, SatWorkItem)
        if not isinstance(result, SatCertificate):
            return None

        # Challenge accounting: require matching challenge_id, reject unissued,
        # or mismatched IDs. Duplicate verification is prevented by checking if
        # challenge_id is already in _verified_credits.
        if result.challenge_id != item.challenge_id:
            return None  # mismatch
        if result.challenge_id not in self._issued_ids:
            return None  # unissued
        if result.challenge_id in self._verified_credits:
            return None  # already verified and credited
        owner = self._challenge_owner.get(result.challenge_id)
        if not result.assigned_hotkey or result.assigned_hotkey != owner:
            return None

        instance = item.instance

        # Validator-derived difficulty: clause count — never the miner's claimed
        # work_units. The returned certificate always carries the validator's
        # value so score() never touches a miner-supplied number. Defending
        # against 1e300, NaN, Infinity, negative, or any forged claim.
        validator_work_units = float(len(instance.clauses))
        if not math.isfinite(validator_work_units) or validator_work_units < 0:
            return None  # defense-in-depth (should never happen)

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
            # Record verified credit only after full validation passes.
            self._verified_credits[result.challenge_id] = validator_work_units
            return SatCertificate(
                satisfiable=True,
                assignment=result.assignment,
                work_units=validator_work_units,
                challenge_id=result.challenge_id,
                assigned_hotkey=result.assigned_hotkey,
            )

        # UNSAT claim: testable core re-solves to confirm (Phase-2: DRAT proof).
        if solve_sat(instance) is not None:
            return None
        # Record verified credit only after full validation passes.
        self._verified_credits[result.challenge_id] = validator_work_units
        return SatCertificate(
            satisfiable=False,
            assignment=None,
            work_units=validator_work_units,
            challenge_id=result.challenge_id,
            assigned_hotkey=result.assigned_hotkey,
        )

    def score(self, miner: str, certs: list[Certificate]) -> float:
        """Sum validator-derived work_units for verified certificates only.

        Only certificates that passed verify() are recorded in _verified_credits.
        This ensures that hand-constructed certs with forged work_units, unknown
        challenge_ids, or unverified assignments contribute zero.

        Additionally, each challenge_id is counted at most once per call (deduplication),
        and only when the challenge owner matches the miner being scored.

        Returns the total accumulated work_units, or 0.0 if no verified certs.
        """
        total = 0.0
        seen_challenge_ids: set[str] = set()
        for c in certs:
            # Only count if challenge_id is in the verified_credits map.
            cid = getattr(c, "challenge_id", None)
            if cid in self._verified_credits and cid not in seen_challenge_ids:
                # Only count if this challenge belongs to the miner being scored.
                owner = self._challenge_owner.get(cid)
                if owner == miner:
                    total += self._verified_credits[cid]
                    seen_challenge_ids.add(cid)
        return total
