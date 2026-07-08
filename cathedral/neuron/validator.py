"""Validator neuron (Phase 1+).

Epoch loop: challenge every miner, verify attestation, gate admission, run the
lanes, score verified work through the routing vector, burn the remainder, set
weights. Sybil defense is free — one attested chip_id backs one UID.
See docs/DESIGN.md §4, §5, §6.
"""

from __future__ import annotations


def epoch() -> None:
    # TODO(phase1): for each axon -> issue_nonce, request Evidence, verify();
    #   dedupe by Attested.chip_id (one machine -> one UID);
    #   attestation floor for admitted+live miners;
    # TODO(phase2): run lanes, score, apply ROUTING_VECTOR, burn remainder;
    #   subtensor.set_weights(netuid=39, ...).
    raise NotImplementedError("validator epoch — Phase 1/2")


def main() -> None:
    raise NotImplementedError("validator neuron — Phase 1")


if __name__ == "__main__":
    main()
