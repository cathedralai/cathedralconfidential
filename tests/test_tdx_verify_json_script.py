from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from cathedral.common import report_data

SCRIPT = Path("scripts/tdx_verify_json.py")


def _quote_with_report_data(report_data_bytes: bytes) -> bytes:
    assert len(report_data_bytes) == 64
    return b"\0" * 568 + report_data_bytes + b"\0" * 100


def _fake_attestor_verify(tmp_path: Path) -> Path:
    script = tmp_path / "attestor-verify"
    script.write_text(
        f"""#!{sys.executable}
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

quote_path, report_data_hex, out_path = sys.argv[1:4]
quote = Path(quote_path).read_bytes()
actual = quote[568:632].hex()
Path(out_path).write_text(json.dumps({{
    "intel_verified": os.environ.get("FAKE_INTEL_VERIFIED", "1") == "1",
    "report_data_match": actual == report_data_hex,
    "collateral_urls": ["https://intel.example/collateral"],
    "collateral_b64": "intentionally-dropped",
}}))
""".lstrip()
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_tdx_verify_json_emits_cathedral_claims(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(_quote_with_report_data(rd))

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            "--measurement",
            "tdx-measurement-1",
            "--platform-id",
            "tdx-platform-1",
            "--tcb",
            "7",
            str(quote_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    claims = json.loads(proc.stdout)
    assert claims == {
        "collateral_urls": ["https://intel.example/collateral"],
        "intel_verified": True,
        "measurement": "tdx-measurement-1",
        "platform_id": "tdx-platform-1",
        "report_data": rd.hex(),
        "report_data_match": True,
        "tcb": 7,
    }


def test_tdx_verify_json_fails_closed_without_intel_verdict(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(_quote_with_report_data(rd))
    env = {**os.environ, "FAKE_INTEL_VERIFIED": "0"}

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            "--measurement",
            "tdx-measurement-1",
            "--platform-id",
            "tdx-platform-1",
            "--tcb",
            "7",
            str(quote_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert proc.returncode != 0
    assert "did not verify Intel TDX silicon" in proc.stderr


def test_tdx_verify_json_requires_operator_pinned_metadata(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(_quote_with_report_data(rd))

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            str(quote_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "missing required" in proc.stderr
