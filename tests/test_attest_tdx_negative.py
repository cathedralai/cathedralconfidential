"""Negative controls for the TDX collector.

The first test is hardware-free and locks in the failure mode Cathedral expects
on a host without configfs-tsm. The second is gated for a real non-TDX Linux
box: set CATHEDRAL_RUN_TDX_NEGATIVE=1 there and it must fail before quote
collection.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cathedral.attest import collect_tdx
from cathedral.common import issue_nonce


def test_collect_tdx_fails_cleanly_when_tsm_root_is_missing(tmp_path, monkeypatch):
    missing_root = tmp_path / "missing-report-root"
    monkeypatch.setenv("CATHEDRAL_TDX_TSM_REPORT_ROOT", str(missing_root))

    with pytest.raises(FileNotFoundError, match="configfs-tsm report root not found"):
        collect_tdx(issue_nonce(), "cathedral-non-tdx-negative")


@pytest.mark.skipif(
    os.environ.get("CATHEDRAL_RUN_TDX_NEGATIVE") != "1",
    reason="set CATHEDRAL_RUN_TDX_NEGATIVE=1 on a non-TDX Linux host to run",
)
def test_non_tdx_host_cannot_collect_tdx_evidence():
    report_root = Path(
        os.environ.get("CATHEDRAL_TDX_TSM_REPORT_ROOT", "/sys/kernel/config/tsm/report")
    )
    exposed_tdx_paths = [
        path
        for path in (Path("/sys/module/tdx_guest"), Path("/dev/tdx_guest"), report_root)
        if path.exists()
    ]
    if exposed_tdx_paths:
        exposed = ", ".join(str(path) for path in exposed_tdx_paths)
        pytest.fail(f"host exposes TDX attestation paths; not a non-TDX negative control: {exposed}")

    with pytest.raises(FileNotFoundError, match="configfs-tsm report root not found"):
        collect_tdx(issue_nonce(), "cathedral-non-tdx-negative")
