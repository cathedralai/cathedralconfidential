"""Concrete payload types for the SAT / benchmark lane (docs/DESIGN.md §4).

Pure data, no logic. The lane implementation (cathedral/lanes/sat.py) produces
and checks these. A SAT certificate is *self-certifying*: a claimed satisfying
assignment can be checked against the instance in microseconds, and cannot be
forged (a wrong assignment simply fails a clause).

DIMACS CNF convention
---------------------
Variables are numbered 1..n_vars. A literal is a non-zero int: +v means "var v
true", -v means "var v false". A clause is a list of literals (an OR). An
instance is satisfied when every clause has at least one true literal. An
``assignment`` is a complete list of signed literals, one per variable, e.g.
[1, -2, 3] == {var1=true, var2=false, var3=true}.
"""

from __future__ import annotations

from dataclasses import dataclass

from cathedral.lanes import Certificate, WorkItem


@dataclass(frozen=True)
class SatInstance:
    """A CNF-SAT instance in DIMACS form."""

    n_vars: int
    clauses: list[list[int]]


@dataclass(frozen=True)
class SatWorkItem(WorkItem):
    """A dispatched SAT job: the instance plus the seed it was generated from.

    The seed makes canonical work reproducible — anyone can regenerate the exact
    instance and independently check the returned certificate.

    challenge_id is a deterministic hash of (n_vars, clauses, seed), used to
    prevent duplicate crediting of the same challenge across epochs.
    """

    instance: SatInstance
    seed: int
    challenge_id: str  # sha256 hex digest of instance + seed


@dataclass(frozen=True)
class SatCertificate(Certificate):
    """A miner's claimed result for a SatWorkItem.

    - satisfiable=True  => ``assignment`` must satisfy every clause (checked).
    - satisfiable=False => ``assignment`` is None; the claim is that no
      assignment exists (verified by DRAT proof in production; by re-solving in
      the testable core).

    ``work_units`` is the difficulty-weighted credit for the solve; the lane's
    score() sums it across a miner's accepted certificates.

    ``challenge_id`` echoes the ID from the SatWorkItem to prevent duplicate
    crediting and detect mismatched submissions.
    """

    satisfiable: bool
    assignment: list[int] | None
    work_units: float
    challenge_id: str  # echoed from SatWorkItem
    miner_hotkey: str = ""  # hotkey of the miner that produced this certificate
