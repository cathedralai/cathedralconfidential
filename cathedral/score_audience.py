"""Validation for the network/subnet audience of a score report."""

from __future__ import annotations


MAX_SCORE_NETWORK_LENGTH = 128
MAX_SCORE_NETUID = 2**16 - 1


def validate_score_audience(network: object, netuid: object) -> tuple[str, int]:
    """Return one exact, bounded score audience or fail closed.

    Network names are deliberately not normalized: the producer and consumer
    must agree on the same exact configured value. Restricting the value to
    visible ASCII keeps configuration, logs, and signed JSON unambiguous.
    """

    if (
        not isinstance(network, str)
        or not 1 <= len(network) <= MAX_SCORE_NETWORK_LENGTH
        or network.strip() != network
        or any(not 0x21 <= ord(character) <= 0x7E for character in network)
    ):
        raise ValueError("score network must be a nonempty visible-ASCII string")
    if type(netuid) is not int or not 0 <= netuid <= MAX_SCORE_NETUID:
        raise ValueError(f"score netuid must be an integer between 0 and {MAX_SCORE_NETUID}")
    return network, netuid
