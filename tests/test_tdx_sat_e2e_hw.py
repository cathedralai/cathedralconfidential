"""Hardware-gated TDX -> SAT lane -> emissions round trip.

Run on a TDX CVM only:

    sudo env \
      CATHEDRAL_RUN_TDX_HW=1 \
      CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py' \
      CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify \
      CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<tdx-measurement-sha256:...>' \
      python -m pytest tests/test_tdx_sat_e2e_hw.py -q
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cathedral.common import Policy
from cathedral.neuron.miner import TdxMiner
from cathedral.neuron.validator import attested_epoch


pytestmark = pytest.mark.skipif(
    os.environ.get("CATHEDRAL_RUN_TDX_HW") != "1",
    reason="set CATHEDRAL_RUN_TDX_HW=1 on a TDX CVM to run",
)


def test_tdx_attestation_admits_miner_and_runs_sat_lane():
    report_root = Path(os.environ.get("CATHEDRAL_TDX_TSM_REPORT_ROOT", "/sys/kernel/config/tsm/report"))
    if not report_root.exists():
        pytest.skip("configfs-tsm report root is not available")
    if os.geteuid() != 0 and not os.access(report_root, os.W_OK):
        pytest.skip("configfs-tsm report root requires root or write access")
    if not os.environ.get("CATHEDRAL_TDX_VERIFY_CMD"):
        pytest.skip("CATHEDRAL_TDX_VERIFY_CMD is required")
    measurement = os.environ.get("CATHEDRAL_TDX_ALLOWED_MEASUREMENT")
    if not measurement:
        pytest.skip("CATHEDRAL_TDX_ALLOWED_MEASUREMENT is required")

    result = attested_epoch(
        [TdxMiner(uid="cathedral-tdx-hw-miner", hotkey="cathedral-tdx-hw-hotkey")],
        Policy(
            allowed_measurements={measurement},
            min_tcb=int(os.environ.get("CATHEDRAL_TDX_MIN_TCB", "0")),
        ),
        routing={"sat_benchmark": 1.0},
    )

    assert result.admitted == ["cathedral-tdx-hw-miner"]
    assert result.weights["cathedral-tdx-hw-miner"] > 0
    assert abs(sum(result.weights.values()) + result.burn - 1.0) < 1e-9
