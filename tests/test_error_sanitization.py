"""The secret sanitizer (_sanitize_error) must cover every error rendering path:
default JSON outcomes/runs (_outcome_json, _run_json) and top-level CLI
exceptions (cathedral.cli.main), not just the --pretty text formatter.
"""

from __future__ import annotations

import json

from cathedral.cli import _outcome_json, _run_json, build_parser, main
from cathedral.runtime import EpochRun, MinerOutcome

SECRET = "sk-live-abc123XYZsupersecret"


def _outcome_with_error(error: str | None) -> MinerOutcome:
    return MinerOutcome(
        hotkey="5Hotkey",
        endpoint_url="https://1.1.1.1:9001",
        status="attestation_failed",
        admitted=False,
        work_units=0.0,
        score=0.0,
        error=error,
    )


# ---------------------------------------------------------------------------
# _outcome_json: default JSON path must redact, same as --pretty
# ---------------------------------------------------------------------------


def test_outcome_json_redacts_bearer_secret():
    outcome = _outcome_with_error(f"upstream 401: bearer={SECRET}")
    payload = _outcome_json(outcome)
    assert SECRET not in json.dumps(payload)
    assert "[REDACTED]" in payload["error"]


def test_outcome_json_redacts_authorization_header():
    outcome = _outcome_with_error(f"echo: Authorization: Bearer {SECRET}")
    payload = _outcome_json(outcome)
    assert SECRET not in payload["error"]
    assert "[REDACTED]" in payload["error"]


def test_outcome_json_preserves_none_when_no_error():
    outcome = _outcome_with_error(None)
    payload = _outcome_json(outcome)
    assert payload["error"] is None


def test_outcome_json_preserves_nonsecret_error_text():
    outcome = _outcome_with_error("worker returned HTTP 401")
    payload = _outcome_json(outcome)
    assert payload["error"] == "worker returned HTTP 401"


def test_outcome_json_is_still_valid_json_with_secret_present():
    outcome = _outcome_with_error(f"token={SECRET} timeout")
    # Must not raise -- output remains machine-readable JSON.
    encoded = json.dumps(_outcome_json(outcome))
    decoded = json.loads(encoded)
    assert SECRET not in encoded
    assert decoded["error"].startswith("token=[REDACTED]")


# ---------------------------------------------------------------------------
# _run_json: every outcome inside a run is sanitized
# ---------------------------------------------------------------------------


def test_run_json_sanitizes_every_outcome_error():
    outcomes = (
        _outcome_with_error(f"secret={SECRET}"),
        _outcome_with_error(f"hmac={SECRET}"),
        _outcome_with_error(None),
    )
    run = EpochRun(
        epoch_id=1,
        source_epoch=7,
        status="complete",
        outcomes=outcomes,
        scores={},
        published=False,
    )
    payload = _run_json(run)
    encoded = json.dumps(payload)
    assert SECRET not in encoded
    assert encoded.count("[REDACTED]") == 2
    assert payload["outcomes"][2]["error"] is None


# ---------------------------------------------------------------------------
# main(): top-level CLI exceptions are sanitized before printing
# ---------------------------------------------------------------------------


def test_main_sanitizes_secret_in_top_level_exception(monkeypatch, capsys):
    """main() must redact a secret embedded in an exception raised by args.func."""
    import argparse

    def raising_func(_args: argparse.Namespace) -> int:
        raise ValueError(f"publisher rejected request: bearer={SECRET}")

    fake_args = argparse.Namespace(func=raising_func)

    class FakeParser:
        def parse_args(self, argv: list[str] | None = None) -> argparse.Namespace:
            return fake_args

    monkeypatch.setattr("cathedral.cli.build_parser", lambda: FakeParser())

    rc = main([])
    assert rc == 2
    err = capsys.readouterr().err
    assert SECRET not in err
    assert "[REDACTED]" in err
    # Still valid single-line JSON on stderr.
    payload = json.loads(err)
    assert "error" in payload


def test_main_sanitizes_multiple_secrets_and_flattens_newlines(monkeypatch, capsys):
    import argparse

    def raising_func(_args: argparse.Namespace) -> int:
        raise RuntimeError(f"line one\ntoken={SECRET}\nAuthorization: Bearer {SECRET}")

    fake_args = argparse.Namespace(func=raising_func)

    class FakeParser:
        def parse_args(self, argv: list[str] | None = None) -> argparse.Namespace:
            return fake_args

    monkeypatch.setattr("cathedral.cli.build_parser", lambda: FakeParser())

    rc = main([])
    assert rc == 2
    err = capsys.readouterr().err
    assert SECRET not in err
    assert err.count("[REDACTED]") == 2
    # main() prints one JSON line; no embedded raw newlines from the exception.
    assert len(err.strip().splitlines()) == 1


def test_main_error_output_remains_valid_json_for_a_real_failure(capsys):
    """A genuine failure (unopenable ledger path) still yields sanitized, valid JSON."""
    rc = main(["runtime", "status", "--ledger-db", "/nonexistent/dir/should/not/exist.sqlite"])
    assert rc == 2
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert isinstance(payload["error"], str)
