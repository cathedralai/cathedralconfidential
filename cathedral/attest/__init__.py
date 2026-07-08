"""Miner-side attestation collectors (Phase 1).

Each collector produces an `Evidence` with the validator's challenge bound into
REPORT_DATA. Vendors do the crypto; we orchestrate. See docs/DESIGN.md §6.

Development requires real hardware. Launch path is TDX CPU first because the
live Cathedral box is a GCP TDX CVM; SNP and GPU-CC follow the same interface.
"""

from __future__ import annotations

import os
from pathlib import Path

from cathedral.common import Evidence, EvidenceKind, report_data

_DEFAULT_TSM_REPORT_ROOT = Path("/sys/kernel/config/tsm/report")


def collect_snp(nonce: bytes, hotkey: str, ssh_host_key: bytes | None = None) -> Evidence:
    """AMD SEV-SNP report via /dev/sev-guest with bound REPORT_DATA.

    TODO(phase1): call snpguest / ioctl(/dev/sev-guest) with
    report_data(nonce, hotkey, ssh_host_key); attach the VCEK cert chain.
    """

    _ = report_data(nonce, hotkey, ssh_host_key)
    raise NotImplementedError("SNP collector — Phase 1, needs an SNP-capable EPYC box")


def collect_tdx(nonce: bytes, hotkey: str, ssh_host_key: bytes | None = None) -> Evidence:
    """Intel TDX quote via configfs-tsm (TDG.MR.REPORT -> TDREPORT -> DCAP quote).

    This intentionally only collects evidence. DCAP or Trust Authority
    verification happens validator-side in ``cathedral.verify.verify``.
    """

    rd = report_data(nonce, hotkey, ssh_host_key)
    root = Path(os.environ.get("CATHEDRAL_TDX_TSM_REPORT_ROOT", _DEFAULT_TSM_REPORT_ROOT))
    quote, cert_chain = _collect_configfs_tsm_quote(rd, root=root)
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=quote,
        cert_chain=cert_chain,
        nonce=nonce,
        miner_hotkey=hotkey,
        ssh_host_key=ssh_host_key,
    )


def _collect_configfs_tsm_quote(report_data_bytes: bytes, *, root: Path) -> tuple[bytes, list[bytes]]:
    """Collect one TSM quote through Linux configfs-tsm.

    The kernel ABI accepts up to 64 bytes in ``inblob`` and returns the
    implementation-specific quote in ``outblob``. A fresh per-process report
    directory avoids generation-counter races between concurrent requests.
    """

    if len(report_data_bytes) > 64:
        raise ValueError("TDX REPORTDATA must be at most 64 bytes")
    if not root.exists():
        raise FileNotFoundError(f"configfs-tsm report root not found: {root}")

    report_dir = root / f"cathedral-{os.getpid()}"
    report_dir.mkdir(mode=0o700, exist_ok=False)
    try:
        (report_dir / "inblob").write_bytes(report_data_bytes)
        quote = (report_dir / "outblob").read_bytes()
        if not quote:
            raise RuntimeError("configfs-tsm returned an empty TDX quote")

        cert_chain = []
        for name in ("auxblob", "manifestblob", "certs"):
            path = report_dir / name
            if path.exists():
                blob = path.read_bytes()
                if blob:
                    cert_chain.append(blob)
        return quote, cert_chain
    finally:
        report_dir.rmdir()


def collect_gpu_cc(nonce: bytes, hotkey: str) -> Evidence:
    """NVIDIA GPU attestation report via NVML / nvtrust.

    TODO(phase1): pull the GPU attestation report; compose with the host CPU
    TEE quote via Intel Trust Authority into a single JWT (docs/DESIGN.md §6).
    """

    _ = EvidenceKind.GPU_CC
    raise NotImplementedError("GPU CC collector — Phase 1, needs a CC-capable H100/H200")
