#!/usr/bin/env python3
"""Adapt Polaris attestor-verify output to Cathedral's TDX verifier JSON.

The Polaris binary performs Intel-chain verification and report_data matching.
This adapter then parses policy claims from the same verified raw quote bytes.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.verify.tdx_quote import TdxQuoteParseError, parse_tdx_quote


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"attestor-verify did not produce valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("attestor-verify JSON was not an object")
    return parsed


def _run_attestor_verify(bin_path: str, quote: bytes, report_data_hex: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-verify-") as td:
        quote_path = Path(td) / "quote.bin"
        out_path = Path(td) / "verify.json"
        quote_path.write_bytes(quote)
        proc = subprocess.run(
            [bin_path, str(quote_path), report_data_hex, str(out_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            raise SystemExit(f"attestor-verify failed: {stderr[:500]}")
        return _read_json(out_path)


def _require_true(verifier: dict[str, Any], key: str, failure: str) -> None:
    if verifier.get(key) is not True:
        raise SystemExit(failure)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("quote", type=Path, help="raw TDX quote file")
    parser.add_argument(
        "--attestor-verify",
        default=os.environ.get("CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN", "attestor-verify"),
        help="path to Polaris attestor-verify binary",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    quote = args.quote.read_bytes()
    try:
        parsed_quote = parse_tdx_quote(quote)
    except TdxQuoteParseError as exc:
        raise SystemExit(str(exc)) from exc

    report_data_hex = parsed_quote.report_data.hex()
    verifier = _run_attestor_verify(args.attestor_verify, quote, report_data_hex)
    _require_true(verifier, "intel_verified", "attestor-verify did not verify Intel TDX silicon")
    _require_true(verifier, "report_data_match", "attestor-verify reported a report_data mismatch")

    print(
        json.dumps(
            {
                "report_data": report_data_hex,
                "measurement": parsed_quote.measurement,
                "tcb": parsed_quote.tcb,
                "tcb_svn": parsed_quote.tcb_svn,
                "platform_id": parsed_quote.platform_id,
                "tdx_pck_cert_id": parsed_quote.platform_id,
                "tdx_attestation_key_id": parsed_quote.attestation_key_id,
                "tdx_certification_data_type": parsed_quote.certification_data_type,
                "mrtd": parsed_quote.body.mr_td.hex(),
                "rtmrs": [rtmr.hex() for rtmr in parsed_quote.body.rtmrs],
                "mr_config_id": parsed_quote.body.mr_config_id.hex(),
                "mr_owner": parsed_quote.body.mr_owner.hex(),
                "mr_owner_config": parsed_quote.body.mr_owner_config.hex(),
                "td_attributes": parsed_quote.body.td_attributes.hex(),
                "xfam": parsed_quote.body.xfam.hex(),
                "intel_verified": True,
                "report_data_match": True,
                "collateral_urls": verifier.get("collateral_urls", []),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
