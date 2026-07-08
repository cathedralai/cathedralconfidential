#!/usr/bin/env python3
"""Adapt Polaris attestor-verify output to Cathedral's TDX verifier JSON.

This is a launch adapter, not a TDX quote parser. The Polaris binary performs
Intel-chain verification and report_data matching. Until Cathedral has a full
quote-claim parser, measurement/platform/tcb are explicit operator-pinned
inputs and this script refuses to emit claims without them.
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

TDX_V4_REPORT_DATA_START = 568
TDX_REPORT_DATA_SIZE = 64


def _env_or_arg(value: str | None, env_name: str) -> str:
    selected = value or os.environ.get(env_name, "")
    if not selected:
        raise SystemExit(f"missing required --{env_name.lower().replace('_', '-')} or {env_name}")
    return selected


def _report_data_from_quote(quote: bytes) -> bytes:
    end = TDX_V4_REPORT_DATA_START + TDX_REPORT_DATA_SIZE
    if len(quote) < end:
        raise SystemExit(f"TDX quote too short to contain report_data: {len(quote)} bytes")
    return quote[TDX_V4_REPORT_DATA_START:end]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"attestor-verify did not produce valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("attestor-verify JSON was not an object")
    return parsed


def _run_attestor_verify(bin_path: str, quote_path: Path, report_data_hex: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-verify-") as td:
        out_path = Path(td) / "verify.json"
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("quote", type=Path, help="raw TDX quote file")
    parser.add_argument(
        "--attestor-verify",
        default=os.environ.get("CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN", "attestor-verify"),
        help="path to Polaris attestor-verify binary",
    )
    parser.add_argument(
        "--measurement",
        default=None,
        help="operator-pinned launch measurement (or CATHEDRAL_TDX_MEASUREMENT)",
    )
    parser.add_argument(
        "--platform-id",
        default=None,
        help="stable launch platform id (or CATHEDRAL_TDX_PLATFORM_ID)",
    )
    parser.add_argument(
        "--tcb",
        type=int,
        default=None,
        help="operator-pinned TCB floor value (or CATHEDRAL_TDX_TCB)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    measurement = _env_or_arg(args.measurement, "CATHEDRAL_TDX_MEASUREMENT")
    platform_id = _env_or_arg(args.platform_id, "CATHEDRAL_TDX_PLATFORM_ID")
    tcb_text = str(args.tcb if args.tcb is not None else os.environ.get("CATHEDRAL_TDX_TCB", ""))
    if not tcb_text:
        raise SystemExit("missing required --tcb or CATHEDRAL_TDX_TCB")

    quote = args.quote.read_bytes()
    report_data_hex = _report_data_from_quote(quote).hex()
    verifier = _run_attestor_verify(args.attestor_verify, args.quote, report_data_hex)
    if not bool(verifier.get("intel_verified")):
        raise SystemExit("attestor-verify did not verify Intel TDX silicon")
    if not bool(verifier.get("report_data_match")):
        raise SystemExit("attestor-verify reported a report_data mismatch")

    print(
        json.dumps(
            {
                "report_data": report_data_hex,
                "measurement": measurement,
                "tcb": int(tcb_text, 0),
                "platform_id": platform_id,
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
