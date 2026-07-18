from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from cathedral.common import report_data
from cathedral.verify.tdx_quote import parse_tdx_quote

from tests.tdx_quote_fixtures import synthetic_tdx_quote

SCRIPT = Path("scripts/tdx_verify_json.py")


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
if os.environ.get("FAKE_OVERSIZED_RESULT") == "1":
    Path(out_path).write_bytes(b"{{" + b"x" * 70000)
    raise SystemExit(0)
intel_verified = os.environ.get("FAKE_INTEL_VERIFIED_RAW")
if intel_verified is None:
    intel_verified = os.environ.get("FAKE_INTEL_VERIFIED", "1") == "1"
report_data_match = os.environ.get("FAKE_REPORT_DATA_MATCH_RAW")
if report_data_match is None:
    report_data_match = actual == report_data_hex
Path(out_path).write_text(json.dumps({{
    "intel_verified": intel_verified,
    "report_data_match": report_data_match,
    "collateral_urls": ["https://intel.example/collateral"],
    "collateral_b64": "intentionally-dropped",
    **json.loads(os.environ.get("FAKE_VERIFIER_CLAIMS", "{{}}")),
}}))
""".lstrip()
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_tdx_verify_json_emits_cathedral_claims(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote = synthetic_tdx_quote(report_data=rd)
    quote_path.write_bytes(quote)
    parsed_quote = parse_tdx_quote(quote)

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            str(quote_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    claims = json.loads(proc.stdout)
    assert claims == {
        "advisory_ids": None,
        "claims_bound_to_quote": None,
        "collateral_current": None,
        "collateral_urls": ["https://intel.example/collateral"],
        "debug_enabled": False,
        "intel_verified": True,
        "measurement": parsed_quote.measurement,
        "mr_config_id": parsed_quote.body.mr_config_id.hex(),
        "mr_owner": parsed_quote.body.mr_owner.hex(),
        "mr_owner_config": parsed_quote.body.mr_owner_config.hex(),
        "mrtd": parsed_quote.body.mr_td.hex(),
        "platform_id": parsed_quote.platform_id,
        "platform_identity_kind": "pck_certificate",
        "platform_identity_verified": None,
        "report_data": rd.hex(),
        "report_data_match": True,
        "rtmrs": [rtmr.hex() for rtmr in parsed_quote.body.rtmrs],
        "stable_platform_id": None,
        "tcb": parsed_quote.tcb,
        "tcb_status": None,
        "tcb_svn": parsed_quote.tcb_svn,
        "td_attributes": parsed_quote.body.td_attributes.hex(),
        "tdx_attestation_key_id": parsed_quote.attestation_key_id,
        "tdx_certification_data_type": parsed_quote.certification_data_type,
        "tdx_pck_cert_id": parsed_quote.platform_id,
        "xfam": parsed_quote.body.xfam.hex(),
    }


def test_tdx_verify_json_emits_canonical_stable_identity_and_typed_claims(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(synthetic_tdx_quote(report_data=rd))
    verifier_claims = {
        "stable_platform_id": "vendor-package-id-123",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "tcb_status": "SWHardeningNeeded",
        "advisory_ids": ["INTEL-SA-01234"],
        "collateral_current": True,
    }
    env = {**os.environ, "FAKE_VERIFIER_CLAIMS": json.dumps(verifier_claims)}

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            str(quote_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    claims = json.loads(proc.stdout)
    assert claims["platform_id"] == claims["stable_platform_id"]
    assert claims["stable_platform_id"].startswith("tdx-platform-sha256:")
    assert "vendor-package-id-123" not in proc.stdout
    assert claims["platform_identity_kind"] == "stable"
    assert claims["platform_identity_verified"] is True
    assert claims["claims_bound_to_quote"] is True
    assert claims["tcb_status"] == "SWHardeningNeeded"
    assert claims["advisory_ids"] == ["INTEL-SA-01234"]
    assert claims["collateral_current"] is True


def test_tdx_verify_json_derives_debug_from_quote_not_verifier(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(
        synthetic_tdx_quote(report_data=rd, td_attributes=(1).to_bytes(8, "little"))
    )
    env = {
        **os.environ,
        "FAKE_VERIFIER_CLAIMS": json.dumps({"debug_enabled": False}),
    }

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--attestor-verify",
            str(_fake_attestor_verify(tmp_path)),
            str(quote_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert json.loads(proc.stdout)["debug_enabled"] is True


def test_tdx_verify_json_fails_closed_without_intel_verdict(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(synthetic_tdx_quote(report_data=rd))
    env = {**os.environ, "FAKE_INTEL_VERIFIED": "0"}

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
        env=env,
    )

    assert proc.returncode != 0
    assert "did not verify Intel TDX silicon" in proc.stderr


def test_tdx_verify_json_rejects_oversized_result_file(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(synthetic_tdx_quote(report_data=rd))
    env = {**os.environ, "FAKE_OVERSIZED_RESULT": "1"}

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
        env=env,
    )

    assert proc.returncode != 0
    assert "oversized result file" in proc.stderr


def test_tdx_verify_json_rejects_string_false_verifier_booleans(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(synthetic_tdx_quote(report_data=rd))
    env = {
        **os.environ,
        "FAKE_INTEL_VERIFIED_RAW": "false",
        "FAKE_REPORT_DATA_MATCH_RAW": "false",
    }

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
        env=env,
    )

    assert proc.returncode != 0
    assert "did not verify Intel TDX silicon" in proc.stderr


def test_tdx_verify_json_ignores_operator_pinned_metadata_env(tmp_path):
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_path = tmp_path / "quote.bin"
    quote = synthetic_tdx_quote(report_data=rd)
    quote_path.write_bytes(quote)
    parsed_quote = parse_tdx_quote(quote)
    env = {
        **os.environ,
        "CATHEDRAL_TDX_MEASUREMENT": "garbage",
        "CATHEDRAL_TDX_PLATFORM_ID": "garbage",
        "CATHEDRAL_TDX_TCB": "999999",
    }

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
        env=env,
    )

    assert proc.returncode == 0
    claims = json.loads(proc.stdout)
    assert claims["measurement"] == parsed_quote.measurement
    assert claims["platform_id"] == parsed_quote.platform_id
    assert claims["tcb"] == parsed_quote.tcb
