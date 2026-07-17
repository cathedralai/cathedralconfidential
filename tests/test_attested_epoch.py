"""Contract: real attestation evidence can drive the SAT lane end to end."""

from __future__ import annotations

from dataclasses import dataclass

from cathedral.assurance import attestation_claims
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier
from cathedral.lanes.sat import solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.neuron.validator import attested_epoch


@dataclass
class EvidenceBackedMiner:
    uid: str
    hotkey: str
    chip_id: str
    measurement: str = "tdx-measurement-1"
    tcb: int = 7

    def collect_evidence(self, nonce: bytes) -> Evidence:
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=f"quote:{self.uid}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        assignment = solve_sat(item.instance)
        if assignment is None:
            return SatCertificate(
                satisfiable=False,
                assignment=None,
                work_units=1.0,
                challenge_id=item.challenge_id,
                assigned_hotkey=self.uid,
            )
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
            challenge_id=item.challenge_id,
            assigned_hotkey=self.uid,
        )


def _verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    uid = evidence.quote.decode().split(":", 1)[1]
    miner = _MINERS_BY_UID[uid]
    if evidence.nonce != nonce:
        return None
    if miner.measurement not in policy.allowed_measurements:
        return None
    if miner.tcb < policy.min_tcb:
        return None
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=miner.chip_id,
        measurement=miner.measurement,
        tcb=miner.tcb,
        assurance=attestation_claims(evidence.quote, policy),
    )


_MINERS_BY_UID: dict[str, EvidenceBackedMiner] = {}


def test_attested_epoch_admits_tdx_runs_sat_and_conserves_weights():
    miners = [
        EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1"),
        EvidenceBackedMiner("uid-2", "hotkey-2", "chip-2"),
    ]
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID.update({m.uid: m for m in miners})

    result = attested_epoch(
        miners,
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == ["uid-1", "uid-2"]
    assert set(result.weights) == {"uid-1", "uid-2"}
    assert all(weight > 0 for weight in result.weights.values())
    assert abs(sum(result.weights.values()) + result.burn - 1.0) < 1e-9


def test_attested_epoch_dedupes_same_tdx_platform_id():
    miners = [
        EvidenceBackedMiner("uid-1", "hotkey-1", "shared-chip"),
        EvidenceBackedMiner("uid-2", "hotkey-2", "shared-chip"),
    ]
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID.update({m.uid: m for m in miners})

    result = attested_epoch(
        miners,
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == ["uid-1"]
    assert set(result.weights) == {"uid-1"}


def test_attested_epoch_rejects_bad_measurement_before_work():
    miner = EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1")
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID[miner.uid] = miner

    result = attested_epoch(
        [miner],
        Policy(allowed_measurements={"other-measurement"}, min_tcb=0),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == []
    assert result.weights == {}
    assert result.burn == 1.0


def test_attested_epoch_rejects_legacy_verified_flag_without_assurance():
    miner = EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1")

    def legacy_verifier(
        evidence: Evidence, nonce: bytes, policy: Policy
    ) -> Attested:
        assert evidence.nonce == nonce
        return Attested(
            Tier.CC_CPU_TDX,
            "chip-1",
            "tdx-measurement-1",
            7,
            "VERIFIED",
        )

    result = attested_epoch(
        [miner],
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7),
        routing={"sat_benchmark": 1.0},
        verifier=legacy_verifier,
    )

    assert result.admitted == []
    assert result.weights == {}
    assert result.burn == 1.0
