"""Contract: nonce freshness and REPORT_DATA binding (docs/DESIGN.md §6).

REPORT_DATA = sha512(nonce || hotkey [|| ssh_host_key]) binds freshness, the
registered identity (defeats evidence relay), and the Sandbox SSH channel.
"""

from __future__ import annotations

from cathedral.common import issue_nonce, report_data


def test_nonce_is_32_bytes():
    n = issue_nonce()
    assert isinstance(n, bytes)
    assert len(n) == 32


def test_nonces_are_fresh():
    assert issue_nonce() != issue_nonce()


def test_report_data_is_64_bytes_and_deterministic():
    n = issue_nonce()
    d = report_data(n, "hotkey-1")
    assert isinstance(d, bytes)
    assert len(d) == 64
    assert report_data(n, "hotkey-1") == d  # deterministic in its inputs


def test_hotkey_changes_digest():
    n = issue_nonce()
    assert report_data(n, "hotkey-1") != report_data(n, "hotkey-2")


def test_nonce_changes_digest():
    d = report_data(issue_nonce(), "hotkey-1")
    assert report_data(issue_nonce(), "hotkey-1") != d


def test_ssh_host_key_changes_digest():
    n = issue_nonce()
    bare = report_data(n, "hotkey-1")
    bound = report_data(n, "hotkey-1", b"ssh-host-key-bytes")
    assert bound != bare
    assert len(bound) == 64
