"""Miner-side attestation collectors (Phase 1).

Each collector produces an `Evidence` with the validator's challenge bound into
REPORT_DATA. Vendors do the crypto; we orchestrate. See docs/DESIGN.md §6.

Development requires real hardware (the critical path): an SNP-capable EPYC box
first, then a TDX host and a CC-capable H100/H200.
"""

from __future__ import annotations

from cathedral.common import Evidence, EvidenceKind, report_data


def collect_snp(nonce: bytes, hotkey: str, ssh_host_key: bytes | None = None) -> Evidence:
    """AMD SEV-SNP report via /dev/sev-guest with bound REPORT_DATA.

    TODO(phase1): call snpguest / ioctl(/dev/sev-guest) with
    report_data(nonce, hotkey, ssh_host_key); attach the VCEK cert chain.
    """

    _ = report_data(nonce, hotkey, ssh_host_key)
    raise NotImplementedError("SNP collector — Phase 1, needs an SNP-capable EPYC box")


def collect_tdx(nonce: bytes, hotkey: str, ssh_host_key: bytes | None = None) -> Evidence:
    """Intel TDX quote via configfs-tsm (TDG.MR.REPORT -> TDREPORT -> DCAP quote).

    TODO(phase1): write report_data to /sys/kernel/config/tsm/report/*/inblob,
    read the quote from outblob.
    """

    _ = report_data(nonce, hotkey, ssh_host_key)
    raise NotImplementedError("TDX collector — Phase 1, needs a TDX host")


def collect_gpu_cc(nonce: bytes, hotkey: str) -> Evidence:
    """NVIDIA GPU attestation report via NVML / nvtrust.

    TODO(phase1): pull the GPU attestation report; compose with the host CPU
    TEE quote via Intel Trust Authority into a single JWT (docs/DESIGN.md §6).
    """

    _ = EvidenceKind.GPU_CC
    raise NotImplementedError("GPU CC collector — Phase 1, needs a CC-capable H100/H200")
