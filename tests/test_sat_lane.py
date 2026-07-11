"""Contract: the SAT lane's self-certifying verification (docs/DESIGN.md §4).

A SAT assignment is checkable in microseconds and unforgeable — a wrong
assignment simply fails a clause. UNSAT is verified by re-solving in the
testable core (DRAT proof in production).
"""

from __future__ import annotations

import math
import subprocess
import sys

from cathedral.common import Attested, Tier
from cathedral.lanes.sat import SatLane, solve_sat, _compute_challenge_id
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
    lane = SatLane()
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    assignment = solve_sat(inst)
    assert assignment is not None
    challenge_id = _compute_challenge_id(inst, 0)
    item = SatWorkItem(instance=inst, seed=0, challenge_id=challenge_id)
    lane._issued_ids.add(challenge_id)
    lane._challenge_owner[challenge_id] = "miner-x"
    cert = SatCertificate(satisfiable=True, assignment=assignment, work_units=1.0, challenge_id=challenge_id)
    assert lane.verify(item, cert) is not None


def test_verify_rejects_forged_assignment():
    # clause [1, 2] needs var1 or var2 true; the forged assignment sets both false.
    lane = SatLane()
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    challenge_id = _compute_challenge_id(inst, 0)
    item = SatWorkItem(instance=inst, seed=0, challenge_id=challenge_id)
    lane._issued_ids.add(challenge_id)
    lane._challenge_owner[challenge_id] = "miner-x"
    forged = SatCertificate(satisfiable=True, assignment=[-1, -2, -3], work_units=1.0, challenge_id=challenge_id)
    assert lane.verify(item, forged) is None


def test_verify_rejects_wrong_satisfiable_flag():
    # A satisfiable instance falsely claimed UNSAT must be rejected.
    lane = SatLane()
    inst = SatInstance(n_vars=3, clauses=[[1, 2], [-1, 3], [-2, -3]])
    challenge_id = _compute_challenge_id(inst, 0)
    item = SatWorkItem(instance=inst, seed=0, challenge_id=challenge_id)
    lane._issued_ids.add(challenge_id)
    lane._challenge_owner[challenge_id] = "miner-x"
    wrong = SatCertificate(satisfiable=False, assignment=None, work_units=1.0, challenge_id=challenge_id)
    assert lane.verify(item, wrong) is None


def test_verify_accepts_true_unsat_certificate():
    lane = SatLane()
    inst = SatInstance(n_vars=1, clauses=[[1], [-1]])
    challenge_id = _compute_challenge_id(inst, 0)
    item = SatWorkItem(instance=inst, seed=0, challenge_id=challenge_id)
    lane._issued_ids.add(challenge_id)
    lane._challenge_owner[challenge_id] = "miner-x"
    cert = SatCertificate(satisfiable=False, assignment=None, work_units=1.0, challenge_id=challenge_id)
    assert lane.verify(item, cert) is not None


def test_score_sums_verified_work_units():
    """score() must sum work_units from verified certs only, not hand-constructed ones."""
    lane = SatLane()
    miner = "miner-x"

    # Create and verify two certs to establish them in verified_credits
    # Use dispatch() to ensure proper ownership tracking
    verified_certs = []
    expected_total = 0.0
    for i in range(2):
        item = lane.dispatch(miner, 0)
        assignment = solve_sat(item.instance)
        assert assignment is not None
        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=10.0,  # miner's claim, will be replaced by validator value
            challenge_id=item.challenge_id,
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        expected_total += verified.work_units
        verified_certs.append(verified)

    # Score should sum the validator-derived work_units from all verified certs
    score = lane.score(miner, verified_certs)
    assert score == expected_total


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
    from cathedral.lanes.sat import SatLane, _compute_challenge_id
    from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem

    lane = SatLane()
    # Instance over 2 vars; the forged assignment repeats var 1 with both signs
    # and omits var 2 (still length 2), trying to satisfy a clause dishonestly.
    inst = SatInstance(n_vars=2, clauses=[[1], [-1]])  # actually UNSAT as SAT claim
    challenge_id = _compute_challenge_id(inst, 0)
    item = SatWorkItem(instance=inst, seed=0, challenge_id=challenge_id)
    lane._issued_ids.add(challenge_id)
    lane._challenge_owner[challenge_id] = "miner-x"
    forged = SatCertificate(satisfiable=True, assignment=[1, -1], work_units=2.0, challenge_id=challenge_id)
    assert lane.verify(item, forged) is None


def test_seed_derivation_is_reproducible_across_pythonhashseed():
    """Seed derivation must be stable across different PYTHONHASHSEED values.

    Python's hash() is process-salted and not reproducible. We use HMAC-SHA256
    instead to ensure identical namespace + counter always yields identical seed.
    """
    # Run dispatch() in separate processes with different PYTHONHASHSEED values
    # and verify they produce identical seeds.
    script = (
        "from cathedral.lanes.sat import SatLane; "
        "lane = SatLane('test-namespace'); "
        "item1 = lane.dispatch('miner-x', 0); "
        "print(item1.seed)"
    )
    result1 = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": "0"},
    )
    result2 = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": "999"},
    )
    assert result1.returncode == 0, f"Process 1 failed: {result1.stderr}"
    assert result2.returncode == 0, f"Process 2 failed: {result2.stderr}"
    seed1 = int(result1.stdout.strip())
    seed2 = int(result2.stdout.strip())
    assert seed1 == seed2, f"Seeds differ: {seed1} != {seed2} with different PYTHONHASHSEED"


def test_seed_derivation_varies_with_different_namespaces():
    """Different namespaces must produce different seeds for the same counter."""
    lane1 = SatLane("ns1")
    lane2 = SatLane("ns2")
    item1 = lane1.dispatch("miner-x", 0)
    item2 = lane2.dispatch("miner-x", 0)
    assert item1.seed != item2.seed, "Different namespaces should produce different seeds"


def test_enqueue_rejects_mismatched_challenge_id():
    """enqueue() must validate that challenge_id matches computed hash of instance+seed.

    This prevents both accidental inconsistency and malicious intent to credit
    the same work twice by changing the ID.
    """
    lane = SatLane()
    inst = SatInstance(n_vars=2, clauses=[[1, 2], [-1, -2]])
    correct_id = _compute_challenge_id(inst, 0)
    wrong_id = _compute_challenge_id(inst, 999)

    # Valid enqueue should succeed
    item_ok = SatWorkItem(instance=inst, seed=0, challenge_id=correct_id)
    lane.enqueue(item_ok)  # Should not raise

    # Invalid enqueue should raise ValueError
    item_bad = SatWorkItem(instance=inst, seed=0, challenge_id=wrong_id)
    try:
        lane.enqueue(item_bad)
        assert False, "enqueue should reject mismatched challenge_id"
    except ValueError as e:
        assert "challenge_id mismatch" in str(e)


def test_score_only_counts_verified_certificates():
    """score() must only count certificates that passed verify().

    Hand-constructed certs with forged work_units, unknown challenge_ids, or
    unverified assignments must contribute zero to the score.
    """
    lane = SatLane()
    miner = "miner-x"

    # Dispatch and verify a legitimate cert
    item = lane.dispatch(miner, 0)
    assignment = solve_sat(item.instance)
    assert assignment is not None

    cert_good = SatCertificate(
        satisfiable=True,
        assignment=assignment,
        work_units=100.0,  # miner's claim is ignored
        challenge_id=item.challenge_id,
    )
    verified = lane.verify(item, cert_good)
    assert verified is not None
    # verify() replaces work_units with validator-derived value (clause count)
    assert verified.work_units > 0
    expected_work_units = verified.work_units

    # Create a hand-constructed cert with forged work_units and unknown ID
    cert_forged = SatCertificate(
        satisfiable=True,
        assignment=assignment,
        work_units=1e300,
        challenge_id="unknown-id",
    )

    # Score should only count the verified cert, ignore the forged one
    score = lane.score(miner, [verified, cert_forged])
    assert score == expected_work_units, f"Expected {expected_work_units}, got {score}"


def test_score_rejects_forged_work_units_in_unverified_cert():
    """score() must reject any cert with challenge_id not in verified_credits.

    Even if work_units looks finite and positive, if the cert was not returned
    by verify(), it contributes zero.
    """
    lane = SatLane()

    # Create a cert that looks valid but was never verified
    fake_cert = SatCertificate(
        satisfiable=True,
        assignment=[1, 2, 3],
        work_units=999.0,
        challenge_id="fake-id",
    )

    # Score must be zero because this cert was never verified
    score = lane.score("miner-x", [fake_cert])
    assert score == 0.0, f"Unverified cert should contribute zero; got {score}"


def test_score_ignores_infinite_work_units_in_hand_constructed_cert():
    """score() ignores certs not in verified_credits, regardless of work_units value.

    This defends against claims like work_units=1e300, NaN, Infinity, or negative.
    Since these certs are not in verified_credits, they contribute zero regardless.
    """
    lane = SatLane()

    # Create certs with various invalid work_units values
    certs = [
        SatCertificate(satisfiable=True, assignment=[1], work_units=math.inf, challenge_id="inf"),
        SatCertificate(satisfiable=True, assignment=[1], work_units=math.nan, challenge_id="nan"),
        SatCertificate(satisfiable=True, assignment=[1], work_units=1e300, challenge_id="huge"),
        SatCertificate(satisfiable=True, assignment=[1], work_units=-999.0, challenge_id="neg"),
    ]

    # All must be ignored (not in verified_credits), so score is zero
    score = lane.score("miner-x", certs)
    assert score == 0.0, f"Unverified certs with invalid work_units should score zero; got {score}"


def test_score_accumulates_multiple_verified_certs():
    """score() correctly accumulates work_units from multiple verified certs."""
    lane = SatLane()
    miner = "miner-x"

    # Create and verify multiple certs using dispatch()
    verified_certs = []
    total_expected = 0.0
    for i in range(3):
        item = lane.dispatch(miner, 0)
        assignment = solve_sat(item.instance)
        assert assignment is not None
        cert = SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=10.0,  # miner's claim, will be replaced by validator value
            challenge_id=item.challenge_id,
        )
        verified = lane.verify(item, cert)
        assert verified is not None
        # verify() replaces work_units with validator-derived value (clause count)
        total_expected += verified.work_units
        verified_certs.append(verified)

    score = lane.score(miner, verified_certs)
    # Should sum up all validator-derived work_units from all certs
    assert score == total_expected, f"Expected {total_expected}, got {score}"
