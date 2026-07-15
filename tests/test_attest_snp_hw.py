"""Hardware-gated AMD SEV-SNP attestation round trip + rejection contract.

Run inside an SEV-SNP guest only (needs /dev/sev-guest and snpguest with
outbound HTTPS to AMD KDS for the cert-chain check):

    CATHEDRAL_RUN_SNP_HW=1 \
    CATHEDRAL_SNPGUEST=/path/to/snpguest \
    python -m pytest tests/test_attest_snp_hw.py -q

The positive round trip proves ``collect_snp`` binds REPORT_DATA and produces a
report the shared ``verify`` path admits (AMD KDS / VCEK chain). The negative
controls are the SNP compatibility contract: a report bound to a different
nonce / hotkey, or whose measurement is outside the policy, must be rejected.

The whole module shares a single collected report via the ``collected`` fixture:
one live ``collect_snp`` per assertion would burst AMD KDS (a VCEK/CA fetch each)
and rate-limit the positive chain check. ``verify`` re-derives REPORT_DATA from
the evidence, so one report drives both the positive round trip and the
report_data-mismatch negatives without a fresh collection each time.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from cathedral.attest import collect_snp
from cathedral.common import EvidenceKind, Policy, Tier, issue_nonce, report_data
from cathedral.verify import verify
from cathedral.verify.snp import parse_snp_report

pytestmark = pytest.mark.skipif(
    os.environ.get("CATHEDRAL_RUN_SNP_HW") != "1",
    reason="set CATHEDRAL_RUN_SNP_HW=1 inside an SEV-SNP guest to run",
)

HOTKEY = "cathedral-snp-hw-test"


@pytest.fixture(scope="module")
def collected():
    """One live SNP collection shared across the module (see module docstring)."""
    if not Path("/dev/sev-guest").exists():
        pytest.skip("/dev/sev-guest is not available (not an SEV-SNP guest)")
    nonce = issue_nonce()
    return nonce, collect_snp(nonce, HOTKEY)


def _policy_for(quote: bytes) -> Policy:
    """Pin the policy to the collected report (self-contained round trip)."""
    parsed = parse_snp_report(quote)
    return Policy(allowed_measurements={parsed.measurement}, min_tcb=parsed.tcb.reported)


def test_collect_snp_binds_report_data(collected):
    nonce, evidence = collected
    assert evidence.kind is EvidenceKind.SEV_SNP
    assert len(evidence.quote) == 1184
    assert evidence.miner_hotkey == HOTKEY
    parsed = parse_snp_report(evidence.quote)
    assert parsed.report_data == report_data(nonce, HOTKEY)
    assert parsed.chip_id  # real physical-CPU id (sybil-dedup key)


def test_collect_snp_then_verify_round_trips_to_attested(collected):
    nonce, evidence = collected
    attested = verify(evidence, nonce, _policy_for(evidence.quote))

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_SNP
    assert attested.chip_id
    assert attested.chain_verified, "AMD KDS VCEK chain must verify on the box"


def test_verify_rejects_wrong_nonce(collected):
    _, evidence = collected
    assert verify(evidence, issue_nonce(), _policy_for(evidence.quote)) is None


def test_verify_rejects_wrong_hotkey(collected):
    nonce, evidence = collected
    tampered = replace(evidence, miner_hotkey=HOTKEY + "-other")
    assert verify(tampered, nonce, _policy_for(evidence.quote)) is None


def test_verify_rejects_measurement_outside_policy(collected):
    nonce, evidence = collected
    off_policy = Policy(allowed_measurements={"00" * 48}, min_tcb=0)
    assert verify(evidence, nonce, off_policy) is None
