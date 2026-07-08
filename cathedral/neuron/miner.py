"""Miner neuron (Phase 1+).

Inverted trust topology vs. the Basilica-lineage fork: the miner *serves*
attestation on request and runs lane work; the validator never SSHes in.
See docs/DESIGN.md §4, §9.

    register on SN39  ->  serve /evidence + /info  ->  subscribe to lanes  ->  do work
"""

from __future__ import annotations


def main() -> None:
    # TODO(phase1): bittensor registration; serve an authenticated attestation
    # endpoint (attest.collect_* bound to the validator's nonce + this hotkey);
    # advertise tier + lane subscriptions.
    raise NotImplementedError("miner neuron — Phase 1")


if __name__ == "__main__":
    main()
