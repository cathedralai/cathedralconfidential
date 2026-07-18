#!/usr/bin/env python3
"""Compute the pinned digest for an installed production TDX verifier."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.verify import tdx_verifier_implementation_digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command",
        required=True,
        help="absolute static production verifier executable",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        help="same absolute static verifier path (exactly one)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = tuple(shlex.split(args.command))
    artifacts = tuple(args.artifact)
    digest = tdx_verifier_implementation_digest(command, artifacts)
    print(
        json.dumps(
            {
                "artifacts": list(artifacts),
                "command": list(command),
                "digest": digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
