#!/usr/bin/env python3
"""Adapt Polaris attestor-verify output to Cathedral's TDX verifier JSON.

The Polaris binary performs Intel-chain verification and report_data matching.
This adapter then parses policy claims from the same verified raw quote bytes.
"""

from __future__ import annotations

import argparse
import hashlib
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


def _exact_optional_bool(verifier: dict[str, Any], key: str) -> bool | None:
    value = verifier.get(key)
    return value if isinstance(value, bool) else None


def _exact_optional_str(verifier: dict[str, Any], key: str) -> str | None:
    value = verifier.get(key)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    return value


def _exact_optional_str_list(verifier: dict[str, Any], key: str) -> list[str] | None:
    value = verifier.get(key)
    if not isinstance(value, list) or len(value) > 64 or any(
        not isinstance(item, str)
        or not item
        or len(item) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
        for item in value
    ):
        return None
    if len(set(value)) != len(value):
        return None
    return value


def _canonical_platform_id(stable_platform_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"cathedral-tdx-platform-v1\0")
    digest.update(stable_platform_id.encode("utf-8"))
    return "tdx-platform-sha256:" + digest.hexdigest()


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

    stable_platform_id = _exact_optional_str(verifier, "stable_platform_id")
    platform_identity_verified = _exact_optional_bool(verifier, "platform_identity_verified")
    claims_bound_to_quote = _exact_optional_bool(verifier, "claims_bound_to_quote")
    stable_identity = (
        stable_platform_id is not None
        and platform_identity_verified is True
        and claims_bound_to_quote is True
    )
    canonical_platform_id = (
        _canonical_platform_id(stable_platform_id) if stable_identity else None
    )

    print(
        json.dumps(
            {
                "report_data": report_data_hex,
                "measurement": parsed_quote.measurement,
                "tcb": parsed_quote.tcb,
                "tcb_svn": parsed_quote.tcb_svn,
                "platform_id": canonical_platform_id or parsed_quote.platform_id,
                "stable_platform_id": canonical_platform_id,
                "platform_identity_kind": "stable" if stable_identity else "pck_certificate",
                "platform_identity_verified": platform_identity_verified,
                "claims_bound_to_quote": claims_bound_to_quote,
                "tdx_pck_cert_id": parsed_quote.platform_id,
                "tdx_attestation_key_id": parsed_quote.attestation_key_id,
                "tdx_certification_data_type": parsed_quote.certification_data_type,
                "mrtd": parsed_quote.body.mr_td.hex(),
                "rtmrs": [rtmr.hex() for rtmr in parsed_quote.body.rtmrs],
                "mr_config_id": parsed_quote.body.mr_config_id.hex(),
                "mr_owner": parsed_quote.body.mr_owner.hex(),
                "mr_owner_config": parsed_quote.body.mr_owner_config.hex(),
                "td_attributes": parsed_quote.body.td_attributes.hex(),
                "debug_enabled": parsed_quote.debug_enabled,
                "xfam": parsed_quote.body.xfam.hex(),
                "tcb_status": _exact_optional_str(verifier, "tcb_status"),
                "advisory_ids": _exact_optional_str_list(verifier, "advisory_ids"),
                "collateral_current": _exact_optional_bool(verifier, "collateral_current"),
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
