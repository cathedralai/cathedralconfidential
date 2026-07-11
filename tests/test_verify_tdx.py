"""Contract: TDX verifier adapter enforces Cathedral policy after vendor crypto.

The real DCAP / Trust Authority verifier stays outside Python. These tests use
a fake command that returns already-verified JSON claims so the hardware-free
suite can pin Cathedral's binding and policy checks.
"""

from __future__ import annotations

import sys

import pytest

from cathedral.common import Evidence, EvidenceKind, Policy, Tier, issue_nonce, report_data
from cathedral.verify import verify


def _fake_verifier(tmp_path):
    script = tmp_path / "fake_tdx_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import json
import os
import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)
print(json.dumps({
    "report_data": os.environ["FAKE_REPORT_DATA"],
    "measurement": os.environ["FAKE_MEASUREMENT"],
    "tcb": int(os.environ["FAKE_TCB"]),
    **({"tcb_svn": os.environ["FAKE_TCB_SVN"]} if "FAKE_TCB_SVN" in os.environ else {}),
    **({"tcb_status": os.environ["FAKE_TCB_STATUS"]} if "FAKE_TCB_STATUS" in os.environ else {}),
    "platform_id": os.environ["FAKE_PLATFORM_ID"],
    "intel_verified": os.environ.get("FAKE_INTEL_VERIFIED", "true").lower() == "true",
    "report_data_match": os.environ.get("FAKE_REPORT_DATA_MATCH", "true").lower() == "true",
}))
""".lstrip()
    )
    return f"{sys.executable} {script}"


def test_tdx_verify_accepts_verified_claims(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    attested = verify(evidence, nonce, policy)

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id == "tdx-platform-1"
    assert attested.measurement == "tdx-measurement-1"
    assert attested.tcb == 7


def test_tdx_verify_rejects_wrong_report_data(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(issue_nonce(), hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_disallowed_measurement(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"other-measurement"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_positive_tcb_floor_for_raw_tcb_svn(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "999")
    monkeypatch.setenv("FAKE_TCB_SVN", "0d010800000000000000000000000000")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=1)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_explicit_failed_intel_verdict(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")
    monkeypatch.setenv("FAKE_INTEL_VERIFIED", "false")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_explicit_report_data_mismatch(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")
    monkeypatch.setenv("FAKE_REPORT_DATA_MATCH", "false")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_requires_external_verifier(monkeypatch):
    nonce = issue_nonce()
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_CMD", raising=False)
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, "hotkey-tdx")

    with pytest.raises(NotImplementedError):
        verify(evidence, nonce, Policy(allowed_measurements={"m"}))


def test_tdx_verify_rejects_unbounded_stdout_output(tmp_path, monkeypatch):
    """Verify that a child writing excessive stdout is killed and rejected."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "spam_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 512 KB to stdout (exceeds typical 1 MB cap when combined with stderr)
for _ in range(64):
    print("x" * 8192)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected due to excessive output
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_unbounded_stderr_output(tmp_path, monkeypatch):
    """Verify that a child writing excessive stderr is killed and rejected."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "spam_stderr_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 512 KB to stderr
for _ in range(64):
    print("y" * 8192, file=sys.stderr)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected due to excessive stderr
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_unbounded_concurrent_output(tmp_path, monkeypatch):
    """Verify that concurrent stdout+stderr writes are capped together."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "concurrent_spam_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys
import threading

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 300 KB to stdout and 300 KB to stderr concurrently
def spam_stdout():
    for _ in range(38):
        print("a" * 8192)

def spam_stderr():
    for _ in range(38):
        print("b" * 8192, file=sys.stderr)

t1 = threading.Thread(target=spam_stdout)
t2 = threading.Thread(target=spam_stderr)
t1.start()
t2.start()
t1.join()
t2.join()
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected; combined output exceeds cap
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_accepts_output_within_cap(tmp_path, monkeypatch):
    """Verify that output within the cap is accepted and parsed normally."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "ok_verifier.py"
    script.write_text(
        f"""
from __future__ import annotations

import json
import os
import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Output a valid JSON response plus a small warning on stderr
print(json.dumps({{
    "report_data": "{report_data(nonce, hotkey).hex()}",
    "measurement": "tdx-measurement-1",
    "tcb": 7,
    "platform_id": "tdx-platform-1",
    "intel_verified": True,
    "report_data_match": True,
}}))

print("Warning: this is a test", file=sys.stderr)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "1048576")  # 1 MB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    attested = verify(evidence, nonce, policy)

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id == "tdx-platform-1"
    assert attested.measurement == "tdx-measurement-1"
    assert attested.tcb == 7


# ---------------------------------------------------------------------------
# Regression tests for the race-free bounded reader
# ---------------------------------------------------------------------------


def test_tdx_verify_rejects_fast_exit_overflow(tmp_path, monkeypatch):
    """Child writes 500 bytes then exits immediately; cap=100 must reject it.

    Regression: old drain path read remaining stdout/stderr after proc.wait()
    without updating combined_bytes, letting a fast-exit child bypass the cap.
    """
    script = tmp_path / "fast_exit.py"
    script.write_text(
        """\
import sys
open(sys.argv[-1], "rb").read()  # consume quote arg
sys.stdout.buffer.write(b"x" * 500)
sys.stdout.buffer.flush()
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")

    nonce = issue_nonce()
    hotkey = "hotkey-overflow"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_101_bytes_accepts_100(tmp_path, monkeypatch):
    """Exact boundary: 101 bytes rejected, exactly 100 bytes accepted.

    Regression: old hard_limit = max_output + 1024 accepted output between
    max_output and max_output+1024, breaking the stated byte cap.
    """
    import shlex
    import os
    import tempfile
    from cathedral.verify import _read_bounded_subprocess

    def _make_script(n_bytes: int) -> str:
        s = tmp_path / f"boundary_{n_bytes}.py"
        s.write_text(
            f"""\
import sys
open(sys.argv[-1], "rb").read()
sys.stdout.buffer.write(b"z" * {n_bytes})
sys.stdout.buffer.flush()
"""
        )
        return f"{sys.executable} {s}"

    nonce = issue_nonce()
    hotkey = "hotkey-boundary"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)

    # 101 bytes against a 100-byte cap must be rejected via verify()
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _make_script(101))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")
    assert verify(evidence, nonce, policy) is None

    # Exactly 100 bytes must not be rejected by the cap.
    with tempfile.TemporaryDirectory() as td:
        quote_path = os.path.join(td, "quote.bin")
        with open(quote_path, "wb") as f:
            f.write(b"tdx-quote")
        stdout, stderr, rc = _read_bounded_subprocess(
            shlex.split(_make_script(100)) + [quote_path], 100, 10
        )
    assert rc == 0
    assert len(stdout.encode()) == 100


def test_tdx_verify_combined_stdout_stderr_cap(tmp_path, monkeypatch):
    """50 bytes stdout + 51 bytes stderr = 101 combined; cap=100 must reject.

    Regression: combined counter must track both streams together, not each
    stream independently.
    """
    script = tmp_path / "split_output.py"
    script.write_text(
        """\
import sys
open(sys.argv[-1], "rb").read()
sys.stdout.buffer.write(b"a" * 50)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b"b" * 51)
sys.stderr.buffer.flush()
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")

    nonce = issue_nonce()
    hotkey = "hotkey-combined"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_timeout_kills_child(tmp_path, monkeypatch):
    """Child that sleeps forever is killed promptly on timeout; no zombie.

    Regression: daemon thread + 1 s join could leave the child running if
    proc.wait() raised TimeoutExpired before the reader thread noticed.
    """
    import time

    script = tmp_path / "sleep_forever.py"
    script.write_text(
        """\
import time, sys
open(sys.argv[-1], "rb").read()
time.sleep(3600)
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_TIMEOUT", "1")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "1048576")

    nonce = issue_nonce()
    hotkey = "hotkey-timeout"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)

    t0 = time.monotonic()
    result = verify(evidence, nonce, policy)
    elapsed = time.monotonic() - t0

    assert result is None  # timeout causes rejection
    assert elapsed < 5, f"timeout took {elapsed:.1f}s, expected <5"
