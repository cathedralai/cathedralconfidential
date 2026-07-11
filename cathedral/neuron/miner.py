"""Miner neuron (Phase 1+).

Inverted trust topology: the miner *serves* attestation on request and runs
lane work; the validator never SSHes in.
See docs/DESIGN.md §4, §9.

    register on SN39  ->  serve /evidence + /info  ->  subscribe to lanes  ->  do work

Hardware-free testable core: ``MockMiner`` serves MOCK evidence (the real
REPORT_DATA binding + policy check, no vendor crypto) and does real SAT work.
The MOCK boundary is the only substitution — the SAT solve/certify path is the
real Phase-2 code. ``main`` (real registration + hardware collectors) stays a
Phase-1 stub with clear markers.
"""

from __future__ import annotations

from dataclasses import dataclass

from cathedral.attest import collect_tdx
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier
from cathedral.lanes.sat import solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.verify.mock import mock_evidence, verify_mock


def _solve_sat_work(item: SatWorkItem) -> SatCertificate:
    assignment = solve_sat(item.instance)
    if assignment is None:
        return SatCertificate(
            satisfiable=False,
            assignment=None,
            work_units=1.0,
            challenge_id=item.challenge_id,
        )
    return SatCertificate(
        satisfiable=True,
        assignment=assignment,
        work_units=float(len(item.instance.clauses)),
        challenge_id=item.challenge_id,
    )


@dataclass
class MockMiner:
    """A hardware-free miner: an identity + a mock TEE + a SAT worker.

    Phase-1 swap-in: replace ``serve_evidence`` with a real attestation collector
    (cathedral.attest.collect_*) served over an authenticated axon endpoint, and
    let the validator run the vendor-crypto ``cathedral.verify.verify`` instead of
    ``verify_mock``.
    """

    uid: str
    hotkey: str
    tier: Tier = Tier.CC_CPU_SNP
    kind: EvidenceKind = EvidenceKind.SEV_SNP
    chip_id: str = "mock-chip-0"
    measurement: str = "mock-measurement-0"
    tcb: int = 1

    def serve_evidence(self, nonce: bytes, policy: Policy) -> Attested | None:
        """Answer a validator challenge: build mock evidence bound to the nonce
        and this hotkey, then return the verifier's verdict (None if rejected).

        The MOCK verifier performs the *real* REPORT_DATA binding + measurement/
        TCB policy checks (docs/DESIGN.md §6); only the vendor crypto is skipped.
        """

        evidence = mock_evidence(
            nonce,
            self.hotkey,
            kind=self.kind,
            tier=self.tier,
            chip_id=self.chip_id,
            measurement=self.measurement,
            tcb=self.tcb,
        )
        return verify_mock(evidence, nonce, policy)

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        """Solve a dispatched SAT instance and return a self-certifying result.

        SAT: a satisfying assignment is the certificate (checkable in µs); UNSAT
        is claimed with no assignment (DRAT proof in production).
        """

        return _solve_sat_work(item)


@dataclass
class TdxMiner:
    """A local TDX miner adapter for the launch path.

    It serves raw TDX ``Evidence`` bound to the validator nonce. The validator
    verifies that evidence with DCAP / Trust Authority via ``cathedral.verify``,
    then runs the same SAT work path as the mock miner.
    """

    uid: str
    hotkey: str
    ssh_host_key: bytes | None = None

    def collect_evidence(self, nonce: bytes) -> Evidence:
        return collect_tdx(nonce, self.hotkey, self.ssh_host_key)

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        return _solve_sat_work(item)


def main() -> None:
    # TODO(phase1): bittensor registration; serve an authenticated attestation
    # endpoint (attest.collect_* bound to the validator's nonce + this hotkey);
    # advertise tier + lane subscriptions; run lane work loops.
    raise NotImplementedError("miner neuron main — Phase 1 (real registration + attestation)")


if __name__ == "__main__":
    main()
