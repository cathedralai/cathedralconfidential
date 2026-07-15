"""Miner-side attestation collectors (Phase 1).

Each collector produces an `Evidence` with the validator's challenge bound into
REPORT_DATA. Vendors do the crypto; we orchestrate. See docs/DESIGN.md §6.

Development requires real hardware. Launch path is TDX CPU first because the
live Cathedral box is a GCP TDX CVM; SNP and GPU-CC follow the same interface.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from cathedral.common import Evidence, EvidenceKind, report_data

_DEFAULT_TSM_REPORT_ROOT = Path("/sys/kernel/config/tsm/report")
_DEFAULT_SEV_GUEST_DEV = Path("/dev/sev-guest")
_SNP_REPORT_SIZE = 1184  # fixed AMD SEV-SNP ATTESTATION_REPORT layout (matches verify.snp)


def collect_snp(nonce: bytes, hotkey: str, ssh_host_key: bytes | None = None) -> Evidence:
    """AMD SEV-SNP attestation report via /dev/sev-guest with bound REPORT_DATA.

    Binds ``report_data(nonce, hotkey, ssh_host_key)`` = sha512(nonce ‖ hotkey
    [‖ ssh_host_key]) into the report's 64-byte REPORT_DATA and returns the raw
    1184-byte SEV-SNP report as the ``Evidence.quote`` that
    ``cathedral.verify.verify_snp`` parses and vendor-verifies (AMD KDS / VCEK).

    Like ``collect_tdx``, this intentionally only *collects* evidence — no vendor
    crypto here; the KDS cert-chain signature check happens validator-side in
    ``cathedral.verify.verify``. The VCEK/CA chain is best-effort attached so a
    KDS-unreachable miner still produces usable evidence (the verifier can also
    fetch it from AMD KDS itself).

    Must run inside an SEV-SNP guest (needs ``/dev/sev-guest``). Uses ``snpguest``
    (github.com/virtee/snpguest); override the binary with ``CATHEDRAL_SNPGUEST``.
    """
    rd = report_data(nonce, hotkey, ssh_host_key)  # 64 bytes — the whole binding
    dev = Path(os.environ.get("CATHEDRAL_SEV_GUEST_DEV", _DEFAULT_SEV_GUEST_DEV))
    quote, cert_chain = _collect_snpguest_report(rd, dev=dev)
    return Evidence(
        kind=EvidenceKind.SEV_SNP,
        quote=quote,
        cert_chain=cert_chain,
        nonce=nonce,
        miner_hotkey=hotkey,
        ssh_host_key=ssh_host_key,
    )


def _resolve_snpguest() -> str:
    """Locate the ``snpguest`` binary (CATHEDRAL_SNPGUEST env, then PATH)."""
    env_path = os.environ.get("CATHEDRAL_SNPGUEST")
    if env_path:
        if Path(env_path).is_file() and os.access(env_path, os.X_OK):
            return env_path
        raise FileNotFoundError(f"CATHEDRAL_SNPGUEST is not an executable: {env_path}")
    found = shutil.which("snpguest")
    if not found:
        raise FileNotFoundError(
            "snpguest not found — set CATHEDRAL_SNPGUEST or install "
            "github.com/virtee/snpguest"
        )
    return found


def _collect_snpguest_report(report_data_bytes: bytes, *, dev: Path) -> tuple[bytes, list[bytes]]:
    """Request one SEV-SNP report via ``snpguest`` and best-effort VCEK/CA chain.

    ``report_data_bytes`` (<=64 bytes) is written to a request file and becomes
    the report's REPORT_DATA; the fixed 1184-byte report is read back. The cert
    chain fetch is best-effort — an empty chain is valid (the verifier fetches
    from AMD KDS when needed).
    """
    if len(report_data_bytes) > 64:
        raise ValueError("SNP REPORTDATA must be at most 64 bytes")
    if not dev.exists():
        raise FileNotFoundError(
            f"{dev} missing — collect_snp must run inside an SEV-SNP guest"
        )
    snpguest = _resolve_snpguest()

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        request = work / "request-data.bin"
        request.write_bytes(report_data_bytes)
        report_path = work / "attestation-report.bin"

        # `snpguest report <out> <request>`: request bytes become REPORT_DATA.
        subprocess.run(
            [snpguest, "report", str(report_path), str(request)],
            check=True, capture_output=True, text=True,
        )
        quote = report_path.read_bytes()
        if len(quote) != _SNP_REPORT_SIZE:
            raise RuntimeError(
                f"snpguest returned {len(quote)} bytes, expected {_SNP_REPORT_SIZE}"
            )
        return quote, _fetch_snp_cert_chain(snpguest, report_path, work)


def _fetch_snp_cert_chain(snpguest: str, report_path: Path, work: Path) -> list[bytes]:
    """Best-effort VCEK + CA (ARK/ASK) fetch from AMD KDS. Returns [] on failure."""
    certs = work / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [snpguest, "fetch", "vcek", "DER", str(certs), str(report_path)],
            check=True, capture_output=True, text=True,
        )
        # `fetch ca` argument order varies across snpguest versions; try known forms.
        for cmd in (
            [snpguest, "fetch", "ca", "--report", str(report_path), "DER", str(certs)],
            [snpguest, "fetch", "ca", "DER", str(certs), str(report_path)],
            [snpguest, "fetch", "ca", "DER", str(certs), "milan"],
        ):
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                break
            except subprocess.CalledProcessError:
                continue
    except (OSError, subprocess.CalledProcessError):
        return []
    return [
        f.read_bytes()
        for f in sorted(certs.glob("*"))
        if f.is_file() and f.suffix.lower() in (".der", ".crt", ".pem")
    ]


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

    report_dir = root / f"cathedral-{os.getpid()}-{secrets.token_hex(8)}"
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
