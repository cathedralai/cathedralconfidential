"""Validator-side verifier + measurement policy (Phase 1).

Vendors do the cryptography (AMD KDS cert chains, Intel DCAP / Trust Authority,
NVIDIA NRAS / nvtrust); this module does policy — allowed measurements, minimum
TCB, allowed firmware — and returns an `Attested` verdict or None.
See docs/DESIGN.md §6.
"""

from __future__ import annotations

from cathedral.common import Attested, Evidence, EvidenceKind, Policy, report_data
from cathedral.verify.snp import verify_snp


def verify(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    """Verify one piece of evidence against the policy. None => rejected.

    Steps (per vendor, Phase 1):
      1. vendor-verify the quote's signature + cert chain (KDS / DCAP / NRAS)
      2. check REPORT_DATA == report_data(nonce, evidence.miner_hotkey, ...)
         — freshness + hotkey ownership (defeats evidence relay)
      3. check measurement in policy.allowed_measurements and tcb >= min_tcb
      4. extract chip_id (SNP CHIP_ID / TDX platform id / GPU UUID) for
         free sybil defense (one machine -> one UID)

    Unsupported evidence kinds return None. They are rejections, not process
    errors, so one miner cannot kill the prober loop.
    """

    expected = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    _ = expected  # bound-in check happens against the parsed quote in Phase 1

    if evidence.kind is EvidenceKind.SEV_SNP:
        return verify_snp(evidence, nonce, policy)
    if evidence.kind is EvidenceKind.TDX:
        return None
    if evidence.kind is EvidenceKind.GPU_CC:
        return None
    return None
