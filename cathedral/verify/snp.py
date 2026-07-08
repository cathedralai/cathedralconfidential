"""AMD SEV-SNP attestation report parsing and verification.

The verifier owns Cathedral policy and nonce binding. AMD owns the signature
chain: when ``snpguest`` is available, this module shells out to it instead of
hand-rolling vendor crypto. See docs/DESIGN.md §6 and HANDOFF.md §4.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from cathedral.common import Attested, Evidence, Policy, Tier, report_data


SNP_REPORT_SIZE = 1184
REPORT_DATA_OFFSET = 0x50
REPORT_DATA_SIZE = 64
MEASUREMENT_OFFSET = 0x90
MEASUREMENT_SIZE = 48
CHIP_ID_OFFSET = 0x1A0
CHIP_ID_SIZE = 64
SIGNATURE_OFFSET = 0x2A0
SIGNATURE_SIZE = 512

VERIFIED = "VERIFIED"
STRUCTURE_OK_CHAIN_UNVERIFIED = "STRUCTURE_OK_CHAIN_UNVERIFIED"


@dataclass(frozen=True)
class SnpTcb:
    """Raw TCB values carried by the SNP report."""

    current: int
    reported: int
    committed: int
    launch: int


@dataclass(frozen=True)
class SnpReport:
    """Parsed fields Cathedral needs from an AMD SEV-SNP attestation report."""

    version: int
    guest_svn: int
    guest_policy: int
    vmpl: int
    signature_algo: int
    platform_info: int
    signer_info: int
    report_data: bytes
    measurement: str
    chip_id: str
    tcb: SnpTcb
    signature: bytes


def parse_snp_report(report: bytes) -> SnpReport:
    """Parse the fixed 1184-byte AMD SEV-SNP attestation report layout."""

    if len(report) != SNP_REPORT_SIZE:
        raise ValueError(f"SNP report must be {SNP_REPORT_SIZE} bytes, got {len(report)}")

    version = struct.unpack_from("<I", report, 0x00)[0]
    guest_svn = struct.unpack_from("<I", report, 0x04)[0]
    guest_policy = struct.unpack_from("<Q", report, 0x08)[0]
    vmpl = struct.unpack_from("<I", report, 0x30)[0]
    signature_algo = struct.unpack_from("<I", report, 0x34)[0]
    current_tcb = struct.unpack_from("<Q", report, 0x38)[0]
    platform_info = struct.unpack_from("<Q", report, 0x40)[0]
    signer_info = struct.unpack_from("<I", report, 0x48)[0]
    reported_tcb = struct.unpack_from("<Q", report, 0x180)[0]
    committed_tcb = struct.unpack_from("<Q", report, 0x1E0)[0]
    launch_tcb = struct.unpack_from("<Q", report, 0x1F0)[0]

    report_data = report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE]
    measurement = report[MEASUREMENT_OFFSET : MEASUREMENT_OFFSET + MEASUREMENT_SIZE].hex()
    chip_id = report[CHIP_ID_OFFSET : CHIP_ID_OFFSET + CHIP_ID_SIZE].hex()
    signature = report[SIGNATURE_OFFSET : SIGNATURE_OFFSET + SIGNATURE_SIZE]

    if not any(signature):
        raise ValueError("SNP report signature is empty")

    return SnpReport(
        version=version,
        guest_svn=guest_svn,
        guest_policy=guest_policy,
        vmpl=vmpl,
        signature_algo=signature_algo,
        platform_info=platform_info,
        signer_info=signer_info,
        report_data=report_data,
        measurement=measurement,
        chip_id=chip_id,
        tcb=SnpTcb(
            current=current_tcb,
            reported=reported_tcb,
            committed=committed_tcb,
            launch=launch_tcb,
        ),
        signature=signature,
    )


def _resolve_snpguest(snpguest_path: str | os.PathLike[str] | None) -> str | None:
    if snpguest_path is not None:
        path = os.fspath(snpguest_path)
        return path if Path(path).is_file() and os.access(path, os.X_OK) else None
    env_path = os.environ.get("CATHEDRAL_SNPGUEST")
    if env_path:
        return env_path if Path(env_path).is_file() and os.access(env_path, os.X_OK) else None
    return shutil.which("snpguest")


def _verify_chain_with_snpguest(
    report: bytes,
    *,
    snpguest_path: str,
    certs_dir: str | os.PathLike[str] | None,
) -> bool:
    """Ask snpguest to fetch AMD certs and verify the report signature chain."""

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        report_path = work / "attestation-report.bin"
        report_path.write_bytes(report)
        certs_path = Path(certs_dir) if certs_dir is not None else work / "certs"
        certs_path.mkdir(parents=True, exist_ok=True)

        subprocess.run(
            [snpguest_path, "fetch", "vcek", "DER", str(certs_path), str(report_path)],
            check=True,
            capture_output=True,
            text=True,
        )

        ca_fetch_orders = [
            [snpguest_path, "fetch", "ca", "--report", str(report_path), "DER", str(certs_path)],
            [snpguest_path, "fetch", "ca", "DER", str(certs_path), "turin"],
            [snpguest_path, "fetch", "ca", "DER", str(certs_path), "genoa"],
            [snpguest_path, "fetch", "ca", "DER", str(certs_path), "milan"],
            [snpguest_path, "fetch", "ca", "DER", str(certs_path), str(report_path)],
        ]
        last_error: subprocess.CalledProcessError | None = None
        for cmd in ca_fetch_orders:
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                break
            except subprocess.CalledProcessError as exc:
                last_error = exc
        else:
            if last_error is not None:
                raise last_error

        subprocess.run(
            [snpguest_path, "verify", "certs", str(certs_path)],
            check=True,
            capture_output=True,
            text=True,
        )

        verify_orders = [
            [snpguest_path, "verify", "attestation", str(certs_path), str(report_path)],
            [snpguest_path, "verify", "attestation", str(report_path), str(certs_path)],
        ]
        last_error = None
        for cmd in verify_orders:
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                return True
            except subprocess.CalledProcessError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
    return False


def verify_snp_report_data(
    report: bytes,
    expected_report_data: bytes,
    policy: Policy,
    *,
    snpguest_path: str | os.PathLike[str] | None = None,
    certs_dir: str | os.PathLike[str] | None = None,
) -> Attested | None:
    """Verify a raw SNP report against explicit 64-byte REPORT_DATA."""

    if len(expected_report_data) != REPORT_DATA_SIZE:
        raise ValueError("expected REPORT_DATA must be exactly 64 bytes")

    parsed = parse_snp_report(report)
    if parsed.report_data != expected_report_data:
        return None
    if parsed.measurement not in policy.allowed_measurements:
        return None
    if parsed.tcb.reported < policy.min_tcb:
        return None

    snpguest = _resolve_snpguest(snpguest_path)
    chain_verified = False
    if snpguest is not None:
        for attempt in range(3):
            try:
                chain_verified = _verify_chain_with_snpguest(
                    report,
                    snpguest_path=snpguest,
                    certs_dir=certs_dir,
                )
                break
            except (OSError, subprocess.CalledProcessError):
                if attempt == 2:
                    return None
                time.sleep(1)

    status = VERIFIED if chain_verified else STRUCTURE_OK_CHAIN_UNVERIFIED
    return Attested(
        tier=Tier.CC_CPU_SNP,
        chip_id=parsed.chip_id,
        measurement=parsed.measurement,
        tcb=parsed.tcb.reported,
        verification_status=status,
        chain_verified=chain_verified,
    )


def verify_snp(
    evidence: Evidence,
    nonce: bytes,
    policy: Policy,
    *,
    snpguest_path: str | os.PathLike[str] | None = None,
    certs_dir: str | os.PathLike[str] | None = None,
) -> Attested | None:
    """Verify SNP evidence using the existing Cathedral nonce/hotkey binding."""

    expected = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    return verify_snp_report_data(
        evidence.quote,
        expected,
        policy,
        snpguest_path=snpguest_path,
        certs_dir=certs_dir,
    )
