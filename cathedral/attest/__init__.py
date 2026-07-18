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

from cathedral.common import (
    ChannelBinding,
    Evidence,
    EvidenceKind,
    report_data,
    report_data_v2,
)

_DEFAULT_TSM_REPORT_ROOT = Path("/sys/kernel/config/tsm/report")
_DEFAULT_SEV_GUEST_DEV = Path("/dev/sev-guest")
_SNP_REPORT_SIZE = 1184  # fixed AMD SEV-SNP ATTESTATION_REPORT layout (matches verify.snp)
_TDX_QUOTE_V4_SIGNED_SIZE_OFFSET = 0x278
_TDX_QUOTE_V4_SIGNED_DATA_OFFSET = 0x27C
_MAX_TDX_CONFIGFS_ZERO_PADDING = 4096


def _canonicalize_tdx_configfs_quote(quote: bytes) -> bytes:
    """Remove only bounded all-zero configfs padding from an Intel quote v4.

    Some TDX configfs providers return a fixed-size ``outblob`` and zero-fill
    the bytes after Intel's declared signed-data boundary. Canonicalizing that
    kernel transport padding at collection time preserves the production
    verifier's strict rejection of any unsigned suffix received over the
    network. Malformed, nonzero, oversized, and non-v4 suffixes stay untouched
    so validator-side ABI checks reject them.
    """

    if len(quote) < _TDX_QUOTE_V4_SIGNED_DATA_OFFSET:
        return quote
    if int.from_bytes(quote[:2], "little") != 4:
        return quote
    signed_size = int.from_bytes(
        quote[
            _TDX_QUOTE_V4_SIGNED_SIZE_OFFSET:_TDX_QUOTE_V4_SIGNED_DATA_OFFSET
        ],
        "little",
    )
    canonical_end = _TDX_QUOTE_V4_SIGNED_DATA_OFFSET + signed_size
    if canonical_end > len(quote):
        return quote
    padding = quote[canonical_end:]
    if not padding:
        return quote
    if len(padding) > _MAX_TDX_CONFIGFS_ZERO_PADDING or any(padding):
        return quote
    return quote[:canonical_end]


def _snpguest_timeout() -> float:
    """Wall-clock cap (seconds) for each ``snpguest`` subprocess so a hung binary
    cannot wedge the collector. Override with ``CATHEDRAL_SNPGUEST_TIMEOUT``."""
    try:
        return max(1.0, float(os.environ.get("CATHEDRAL_SNPGUEST_TIMEOUT", "30")))
    except (TypeError, ValueError):
        return 30.0


def collect_snp(
    nonce: bytes,
    hotkey: str,
    ssh_host_key: bytes | None = None,
    *,
    channel_binding: ChannelBinding | None = None,
    report_data_version: int = 1,
) -> Evidence:
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
    if report_data_version == 2:
        if channel_binding is None:
            raise ValueError("report data v2 requires a channel binding")
        rd = report_data_v2(nonce, hotkey, channel_binding)
    elif report_data_version == 1:
        rd = report_data(nonce, hotkey, ssh_host_key)
    else:
        raise ValueError("unsupported report data version")
    dev = Path(os.environ.get("CATHEDRAL_SEV_GUEST_DEV", _DEFAULT_SEV_GUEST_DEV))
    quote, cert_chain = _collect_snpguest_report(rd, dev=dev)
    return Evidence(
        kind=EvidenceKind.SEV_SNP,
        quote=quote,
        cert_chain=cert_chain,
        nonce=nonce,
        miner_hotkey=hotkey,
        ssh_host_key=ssh_host_key,
        report_data_version=report_data_version,
        channel_binding=channel_binding,
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
        try:
            subprocess.run(
                [snpguest, "report", str(report_path), str(request)],
                check=True, capture_output=True, text=True, timeout=_snpguest_timeout(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"snpguest report timed out after {_snpguest_timeout():.0f}s"
            ) from exc
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
    timeout = _snpguest_timeout()
    try:
        subprocess.run(
            [snpguest, "fetch", "vcek", "DER", str(certs), str(report_path)],
            check=True, capture_output=True, text=True, timeout=timeout,
        )
        # `fetch ca` argument order varies across snpguest versions; try the known
        # forms. Both derive the CA generation (Milan / Genoa / Turin) from the
        # report itself — no hardcoded product guess, which would fetch the wrong
        # CA on non-Milan parts.
        for cmd in (
            [snpguest, "fetch", "ca", "--report", str(report_path), "DER", str(certs)],
            [snpguest, "fetch", "ca", "DER", str(certs), str(report_path)],
        ):
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
                break
            except subprocess.CalledProcessError:
                continue
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    return [
        f.read_bytes()
        for f in sorted(certs.glob("*"))
        if f.is_file() and f.suffix.lower() in (".der", ".crt", ".pem")
    ]


def collect_tdx(
    nonce: bytes,
    hotkey: str,
    ssh_host_key: bytes | None = None,
    *,
    channel_binding: ChannelBinding | None = None,
    report_data_version: int = 1,
) -> Evidence:
    """Intel TDX quote via configfs-tsm (TDG.MR.REPORT -> TDREPORT -> DCAP quote).

    This intentionally only collects evidence. DCAP or Trust Authority
    verification happens validator-side in ``cathedral.verify.verify``.
    """

    if report_data_version == 2:
        if channel_binding is None:
            raise ValueError("report data v2 requires a channel binding")
        rd = report_data_v2(nonce, hotkey, channel_binding)
    elif report_data_version == 1:
        rd = report_data(nonce, hotkey, ssh_host_key)
    else:
        raise ValueError("unsupported report data version")
    root = Path(os.environ.get("CATHEDRAL_TDX_TSM_REPORT_ROOT", _DEFAULT_TSM_REPORT_ROOT))
    quote, cert_chain = _collect_configfs_tsm_quote(rd, root=root)
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=quote,
        cert_chain=cert_chain,
        nonce=nonce,
        miner_hotkey=hotkey,
        ssh_host_key=ssh_host_key,
        report_data_version=report_data_version,
        channel_binding=channel_binding,
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
        quote = _canonicalize_tdx_configfs_quote((report_dir / "outblob").read_bytes())
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


def collect_gpu_cc(
    nonce: bytes,
    hotkey: str,
    *,
    channel_binding: ChannelBinding,
    report_data_version: int = 2,
) -> Evidence:
    """Collect bounded NVIDIA evidence for the independent v2 GPU challenge.

    ``CATHEDRAL_GPU_COLLECT_CMD`` names a shell-free external collector. The
    result remains a GPU component; only composite TDX plus GPU verification can
    produce a confidential-GPU admission verdict.
    """

    if report_data_version != 2:
        raise ValueError("confidential GPU evidence requires report data v2")

    from cathedral.gpu import collect_gpu_from_env

    return collect_gpu_from_env(nonce, hotkey, channel_binding)


def collect_tdx_gpu(
    nonce: bytes,
    hotkey: str,
    *,
    channel_binding: ChannelBinding,
    report_data_version: int = 2,
) -> tuple[Evidence, Evidence]:
    """Collect the first supported two-component confidential-GPU bundle."""

    if report_data_version != 2:
        raise ValueError("composite GPU evidence requires report data v2")
    return (
        collect_tdx(
            nonce,
            hotkey,
            channel_binding=channel_binding,
            report_data_version=2,
        ),
        collect_gpu_cc(
            nonce,
            hotkey,
            channel_binding=channel_binding,
            report_data_version=2,
        ),
    )
