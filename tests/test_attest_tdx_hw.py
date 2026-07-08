"""Hardware-gated TDX attestation round trip.

Run on a TDX CVM only:

    CATHEDRAL_RUN_TDX_HW=1 \
    CATHEDRAL_TDX_VERIFY_CMD='tdx-verifier-json' \
    CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<measurement>' \
    python -m pytest tests/test_attest_tdx_hw.py -q
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cathedral.attest import collect_tdx
from cathedral.common import Policy, Tier, issue_nonce
from cathedral.verify import verify


pytestmark = pytest.mark.skipif(
    os.environ.get("CATHEDRAL_RUN_TDX_HW") != "1",
    reason="set CATHEDRAL_RUN_TDX_HW=1 on a TDX CVM to run",
)


def test_collect_tdx_then_verify_round_trips_to_attested():
    if not Path("/sys/kernel/config/tsm/report").exists():
        pytest.skip("configfs-tsm report root is not available")
    if not os.environ.get("CATHEDRAL_TDX_VERIFY_CMD"):
        pytest.skip("CATHEDRAL_TDX_VERIFY_CMD is required")
    measurement = os.environ.get("CATHEDRAL_TDX_ALLOWED_MEASUREMENT")
    if not measurement:
        pytest.skip("CATHEDRAL_TDX_ALLOWED_MEASUREMENT is required")

    nonce = issue_nonce()
    hotkey = "cathedral-tdx-hw-test"

    evidence = collect_tdx(nonce, hotkey)
    attested = verify(
        evidence,
        nonce,
        Policy(
            allowed_measurements={measurement},
            min_tcb=int(os.environ.get("CATHEDRAL_TDX_MIN_TCB", "0")),
        ),
    )

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id
    assert attested.measurement == measurement
