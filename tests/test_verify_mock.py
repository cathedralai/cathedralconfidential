"""Contract: the MOCK attestation path (docs/DESIGN.md §6).

MOCK — the hardware verifier is Phase 1. verify_mock skips vendor crypto but
performs the real REPORT_DATA binding + measurement/TCB policy checks with
cathedral.common logic. Sybil dedup by chip_id is free.
"""

from __future__ import annotations

from cathedral.common import Policy, Tier, issue_nonce
from cathedral.verify.mock import mock_gpu, mock_snp, mock_tdx, verify_mock


def test_accepts_well_formed_evidence():
    nonce = issue_nonce()
    ev = mock_snp(nonce, "hotkey-1", chip_id="chip-1")
    policy = Policy(allowed_measurements={ev.measurement}, min_tcb=ev.tcb)
    att = verify_mock(ev, nonce, policy)
    assert att is not None
    assert att.chip_id == "chip-1"
    assert att.tier == Tier.CC_CPU_SNP
    assert att.measurement == ev.measurement


def test_rejects_wrong_report_data_binding():
    nonce = issue_nonce()
    ev = mock_snp(nonce, "hotkey-1")
    policy = Policy(allowed_measurements={ev.measurement}, min_tcb=0)
    # verifying against a different nonce breaks the freshness/hotkey binding.
    assert verify_mock(ev, issue_nonce(), policy) is None


def test_rejects_sub_min_tcb():
    nonce = issue_nonce()
    ev = mock_tdx(nonce, "hotkey-1")
    policy = Policy(allowed_measurements={ev.measurement}, min_tcb=ev.tcb + 1)
    assert verify_mock(ev, nonce, policy) is None


def test_rejects_disallowed_measurement():
    nonce = issue_nonce()
    ev = mock_gpu(nonce, "hotkey-1")
    policy = Policy(allowed_measurements={"some-other-measurement"}, min_tcb=0)
    assert verify_mock(ev, nonce, policy) is None


def test_fixtures_have_distinct_chip_ids():
    nonce = issue_nonce()
    snp = mock_snp(nonce, "hk")
    tdx = mock_tdx(nonce, "hk")
    gpu = mock_gpu(nonce, "hk")
    assert len({snp.chip_id, tdx.chip_id, gpu.chip_id}) == 3
    assert (snp.tier, tdx.tier, gpu.tier) == (Tier.CC_CPU_SNP, Tier.CC_CPU_TDX, Tier.CC_GPU)


def test_same_chip_id_dedupes_to_one_uid():
    nonce = issue_nonce()
    # two hotkeys fronting for the SAME physical machine (relay/sybil attempt).
    ev_a = mock_snp(nonce, "hotkey-A", chip_id="shared-chip")
    ev_b = mock_snp(nonce, "hotkey-B", chip_id="shared-chip")
    policy = Policy(allowed_measurements={ev_a.measurement}, min_tcb=0)
    att_a = verify_mock(ev_a, nonce, policy)
    att_b = verify_mock(ev_b, nonce, policy)
    assert att_a is not None and att_b is not None

    # admission keys miners by chip_id: one machine backs exactly one UID.
    admitted: dict[str, str] = {}
    for uid, att in [("uid-A", att_a), ("uid-B", att_b)]:
        admitted[att.chip_id] = uid
    assert len(admitted) == 1
