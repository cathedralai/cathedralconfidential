"""Contract: the SAT lane's self-certifying verification (docs/DESIGN.md §4).

A SAT assignment is checkable in microseconds and unforgeable — a wrong
assignment simply fails a clause. UNSAT is verified by re-solving in the
testable core (DRAT proof in production).
"""

from __future__ import annotations

from cathedral.common import Attested, Tier
from cathedral.lanes.sat import SatLane, solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem


def _satisfies(assignment, clauses) -> bool:
    aset = set(assignment)
    return all(any(lit in aset for lit in clause) for clause in clauses)


def test_solver_finds_valid_assignment_for_known_sat():
    inst = SatInstance(n_vars=3, clauses=[[1, -2], [2, 3], [-1, -3]])
    assignment = solve_sat(inst)
    assert assignment is not None
    assert _satisfies(assignment, inst.clauses)


def test_known_unsat_instance_yields_none():
    inst = SatInstance(n_vars=1, clauses=[[1], [-1]])
    assert solve_sat(inst) is None


def test_verify_accepts_true_certificate():
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    assignment = solve_sat(inst)
    assert assignment is not None
    item = SatWorkItem(instance=inst, seed=0)
    cert = SatCertificate(satisfiable=True, assignment=assignment, work_units=1.0)
    assert SatLane().verify(item, cert) is not None


def test_verify_rejects_forged_assignment():
    # clause [1, 2] needs var1 or var2 true; the forged assignment sets both false.
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    item = SatWorkItem(instance=inst, seed=0)
    forged = SatCertificate(satisfiable=True, assignment=[-1, -2, -3], work_units=1.0)
    assert SatLane().verify(item, forged) is None


def test_verify_rejects_wrong_satisfiable_flag():
    # A satisfiable instance falsely claimed UNSAT must be rejected.
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    item = SatWorkItem(instance=inst, seed=0)
    wrong = SatCertificate(satisfiable=False, assignment=None, work_units=1.0)
    assert SatLane().verify(item, wrong) is None


def test_verify_accepts_true_unsat_certificate():
    inst = SatInstance(n_vars=1, clauses=[[1], [-1]])
    item = SatWorkItem(instance=inst, seed=0)
    cert = SatCertificate(satisfiable=False, assignment=None, work_units=1.0)
    assert SatLane().verify(item, cert) is not None


def test_score_sums_work_units():
    certs = [
        SatCertificate(satisfiable=True, assignment=[1], work_units=2.0),
        SatCertificate(satisfiable=True, assignment=[1], work_units=3.0),
    ]
    assert SatLane().score("miner-x", certs) == 5.0


def test_score_of_no_certs_is_zero():
    assert SatLane().score("miner-x", []) == 0.0


def test_qualify_gates_on_cpu_enclave_tiers():
    lane = SatLane()
    assert lane.qualify(Attested(Tier.CC_CPU_SNP, "c", "m", 1))
    assert lane.qualify(Attested(Tier.CC_CPU_TDX, "c", "m", 1))
    assert not lane.qualify(Attested(Tier.CC_GPU, "c", "m", 1))


def test_dispatch_returns_reproducible_canonical_work():
    lane = SatLane()
    item = lane.dispatch("miner-x", budget=0)
    assert isinstance(item, SatWorkItem)
    # canonical instances are satisfiable by construction -> always certifiable.
    assignment = solve_sat(item.instance)
    assert assignment is not None
    assert _satisfies(assignment, item.instance.clauses)


def test_verify_rejects_contradictory_assignment():
    """A cert with both +v and -v for a variable must be rejected even if it
    'satisfies' every clause — it is not a valid Boolean assignment."""
    from cathedral.lanes.sat import SatLane
    from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

    # Instance over 2 vars; the forged assignment repeats var 1 with both signs
    # and omits var 2 (still length 2), trying to satisfy a clause dishonestly.
    inst = SatInstance(n_vars=2, clauses=[[1], [-1]])  # actually UNSAT as SAT claim
    item = SatWorkItem(instance=inst, seed=0)
    forged = SatCertificate(satisfiable=True, assignment=[1, -1], work_units=2.0)
    assert SatLane().verify(item, forged) is None
