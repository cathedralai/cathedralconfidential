"""CC census probe (Phase 0).

Detects confidential-compute capability on the current host so we can measure
launch supply before writing a line of attestation code. Runs anywhere — it
only reads local device nodes and `nvidia-smi`; it does NOT attest. See
docs/DESIGN.md §10 (Phase 0).

    python -m cathedral.census          # human-readable
    python -m cathedral.census --json   # machine-readable

Exit code 0 if any CC capability is detected, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def _sev_snp() -> bool:
    """AMD SEV-SNP guest device, or host SEV parameter enabled."""

    if os.path.exists("/dev/sev-guest"):
        return True
    p = "/sys/module/kvm_amd/parameters/sev_snp"
    try:
        with open(p) as fh:
            return fh.read().strip() in ("1", "Y", "y")
    except OSError:
        return False


def _tdx() -> bool:
    """Intel TDX guest (configfs-tsm report path) or host module present."""

    if os.path.exists("/sys/kernel/config/tsm/report"):
        return True
    return os.path.exists("/sys/module/tdx_guest") or os.path.exists("/dev/tdx_guest")


def _gpu_cc() -> list[str]:
    """GPUs reporting Confidential Compute mode ON via nvidia-smi."""

    try:
        out = subprocess.run(
            ["nvidia-smi", "conf-compute", "-f"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    # Output form varies by driver; treat any "ON"/"enabled" line as CC-capable.
    hits = [ln.strip() for ln in out.stdout.splitlines() if "ON" in ln.upper() or "ENABLED" in ln.upper()]
    return hits


def census() -> dict:
    snp = _sev_snp()
    tdx = _tdx()
    gpu = _gpu_cc()
    return {
        "sev_snp": snp,
        "tdx": tdx,
        "gpu_cc": bool(gpu),
        "gpu_cc_detail": gpu,
        "cc_capable": bool(snp or tdx or gpu),
    }


def main() -> int:
    as_json = "--json" in sys.argv[1:]
    result = census()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("Cathedral CC census")
        print(f"  AMD SEV-SNP : {'yes' if result['sev_snp'] else 'no'}")
        print(f"  Intel TDX   : {'yes' if result['tdx'] else 'no'}")
        print(f"  NVIDIA CC   : {'yes' if result['gpu_cc'] else 'no'}")
        for d in result["gpu_cc_detail"]:
            print(f"                {d}")
        print(f"  => {'CC-CAPABLE' if result['cc_capable'] else 'not CC-capable'}")
    return 0 if result["cc_capable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
