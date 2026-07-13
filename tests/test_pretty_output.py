"""Tests for --pretty human-readable operator output.

Covers:
  - _abbrev, _sanitize_error, _utc_ts helpers
  - _format_run_pretty: success, zero, failure, mixed, field presence, timestamps
  - _format_publish_pretty: success acknowledgement
  - CLI parser: --pretty accepted by run-epoch and retry-publish
  - No bearer / token value leakage in formatted output
"""

from __future__ import annotations

import io
import re

import pytest

from cathedral.cli import (
    _abbrev,
    _format_publish_pretty,
    _format_run_pretty,
    _pretty_outcome_indicator,
    _sanitize_error,
    _utc_ts,
    build_parser,
    _REDACT_PATTERNS,
)
from cathedral.runtime import MAX_BEARER_TOKEN_LENGTH, EpochRun, MinerOutcome, MinerTarget

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]")

LONG_HOTKEY = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
CHALLENGE_ID = "ab" * 32  # 64 hex chars


def _make_run(
    outcomes: list[MinerOutcome],
    *,
    published: bool = False,
    status: str = "complete",
    source_epoch: int = 7,
    epoch_id: int = 1,
) -> EpochRun:
    scores = {o.hotkey: o.score for o in outcomes}
    return EpochRun(
        epoch_id=epoch_id,
        source_epoch=source_epoch,
        status=status,
        outcomes=tuple(outcomes),
        scores=scores,
        published=published,
    )


def _ok_outcome(hotkey: str = LONG_HOTKEY) -> MinerOutcome:
    return MinerOutcome(
        hotkey=hotkey,
        endpoint_url="https://1.1.1.1:9001",
        status="verified",
        admitted=True,
        challenge_id=CHALLENGE_ID,
        work_units=20.0,
        score=1.0,
    )


def _zero_outcome(hotkey: str = "5ZeroNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2zero") -> MinerOutcome:
    return MinerOutcome(
        hotkey=hotkey,
        endpoint_url="https://2.2.2.2:9001",
        status="sat_failed",
        admitted=True,
        challenge_id="cd" * 32,
        work_units=0.0,
        score=0.0,
        error="invalid SAT certificate",
    )


def _fail_outcome(hotkey: str = "5FailNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2fail") -> MinerOutcome:
    return MinerOutcome(
        hotkey=hotkey,
        endpoint_url="https://3.3.3.3:9001",
        status="attestation_failed",
        admitted=False,
        work_units=0.0,
        score=0.0,
        error="worker returned HTTP 401",
    )


# ---------------------------------------------------------------------------
# _utc_ts
# ---------------------------------------------------------------------------


def test_utc_ts_matches_timestamp_pattern():
    ts = _utc_ts()
    assert _TIMESTAMP_RE.match(f"[{ts}]"), f"unexpected format: {ts}"
    assert ts.endswith("Z")


# ---------------------------------------------------------------------------
# _abbrev
# ---------------------------------------------------------------------------


def test_abbrev_short_string_returned_unchanged():
    assert _abbrev("abc", prefix=5, suffix=4) == "abc"


def test_abbrev_none_returns_dash():
    assert _abbrev(None) == "-"


def test_abbrev_empty_returns_dash():
    assert _abbrev("") == "-"


def test_abbrev_long_hotkey():
    result = _abbrev(LONG_HOTKEY, prefix=5, suffix=4)
    # LONG_HOTKEY ends with "wawK"; suffix=4 captures those 4 chars
    assert result == "5Ctob..wawK"
    assert len(result) < len(LONG_HOTKEY)


def test_abbrev_challenge_id():
    result = _abbrev(CHALLENGE_ID, prefix=6, suffix=6)
    assert result == "ababab..ababab"
    assert len(result) < len(CHALLENGE_ID)


def test_abbrev_exactly_at_threshold_returned_unchanged():
    # prefix=3, suffix=3, threshold = 3+3+2 = 8, so 8-char string fits
    s = "12345678"
    assert _abbrev(s, prefix=3, suffix=3) == s


# ---------------------------------------------------------------------------
# _sanitize_error
# ---------------------------------------------------------------------------


def test_sanitize_error_none_returns_empty():
    assert _sanitize_error(None) == ""


def test_sanitize_error_empty_returns_empty():
    assert _sanitize_error("") == ""


def test_sanitize_error_truncates_to_maxlen():
    long_err = "x" * 200
    result = _sanitize_error(long_err, maxlen=100)
    assert len(result) == 100


def test_sanitize_error_strips_newlines():
    result = _sanitize_error("line1\nline2\r\nline3")
    assert "\n" not in result
    assert "\r" not in result
    assert "line1" in result
    assert "line2" in result


def test_sanitize_error_strips_leading_and_trailing_whitespace():
    result = _sanitize_error("  error message  ")
    assert result == "error message"


# ---------------------------------------------------------------------------
# _pretty_outcome_indicator
# ---------------------------------------------------------------------------


def test_indicator_ok_for_admitted_nonzero():
    assert _pretty_outcome_indicator(_ok_outcome()) == "OK  "


def test_indicator_zero_for_admitted_zero_score():
    assert _pretty_outcome_indicator(_zero_outcome()) == "ZERO"


def test_indicator_fail_for_not_admitted():
    assert _pretty_outcome_indicator(_fail_outcome()) == "FAIL"


# ---------------------------------------------------------------------------
# _format_run_pretty: success
# ---------------------------------------------------------------------------


class TestFormatRunPrettySuccess:

    def _format(self, **kw: object) -> str:
        run = _make_run([_ok_outcome()], **kw)
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        return buf.getvalue()

    def test_contains_epoch_start_and_end(self):
        text = self._format()
        assert "EPOCH START" in text
        assert "EPOCH END" in text

    def test_ok_indicator_present(self):
        assert "OK  " in self._format()

    def test_score_formatted(self):
        assert "score=1.000" in self._format()

    def test_work_units_formatted(self):
        assert "wu=   20.00" in self._format()

    def test_summary_counts_correct(self):
        text = self._format()
        assert "ok=1" in text
        assert "zeros=0" in text
        assert "fail=0" in text

    def test_source_epoch_in_header(self):
        assert "source=7" in self._format()

    def test_local_epoch_in_header(self):
        assert "ep=1" in self._format()

    def test_combined_epoch_field_per_worker(self):
        assert "ep=7/1" in self._format()

    def test_hotkey_abbreviated(self):
        text = self._format()
        # Full hotkey must not appear
        assert LONG_HOTKEY not in text
        # Abbreviated prefix must appear
        assert "5Ctob" in text

    def test_challenge_id_abbreviated(self):
        text = self._format()
        assert CHALLENGE_ID not in text
        assert "ababab" in text

    def test_timestamps_in_every_line(self):
        text = self._format()
        for line in text.strip().splitlines():
            assert _TIMESTAMP_RE.match(line), f"no timestamp on line: {line!r}"

    def test_published_no_when_unpublished(self):
        assert "published=NO" in self._format(published=False)

    def test_published_yes_when_published(self):
        run = _make_run([_ok_outcome()], published=True)
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        assert "published=YES" in buf.getvalue()

    def test_pub_field_per_worker_line(self):
        text = self._format(published=False)
        worker_lines = [l for l in text.splitlines() if "OK  " in l or "ZERO" in l or "FAIL" in l]
        assert worker_lines, "expected at least one worker line"
        for line in worker_lines:
            assert "pub=NO" in line

    def test_admit_y_in_worker_line(self):
        assert "admit=Y" in self._format()

    def test_work_status_in_worker_line(self):
        assert "verified" in self._format()

    def test_no_error_part_for_clean_outcome(self):
        text = self._format()
        worker_lines = [l for l in text.splitlines() if "OK  " in l]
        assert worker_lines
        assert "err=" not in worker_lines[0]


# ---------------------------------------------------------------------------
# _format_run_pretty: zero (admitted, score=0)
# ---------------------------------------------------------------------------


class TestFormatRunPrettyZero:

    def _format(self) -> str:
        run = _make_run([_zero_outcome()])
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        return buf.getvalue()

    def test_zero_indicator_present(self):
        assert "ZERO" in self._format()

    def test_summary_zeros_count_correct(self):
        assert "zeros=1" in self._format()

    def test_score_is_zero(self):
        assert "score=0.000" in self._format()

    def test_admit_y_because_admitted(self):
        assert "admit=Y" in self._format()

    def test_error_message_shown(self):
        assert "invalid SAT certificate" in self._format()

    def test_sat_failed_status_shown(self):
        assert "sat_failed" in self._format()

    def test_ok_count_is_zero_fail_count_is_zero(self):
        text = self._format()
        assert "ok=0" in text
        assert "fail=0" in text


# ---------------------------------------------------------------------------
# _format_run_pretty: failure (not admitted, score=0)
# ---------------------------------------------------------------------------


class TestFormatRunPrettyFail:

    def _format(self) -> str:
        run = _make_run([_fail_outcome()])
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        return buf.getvalue()

    def test_fail_indicator_present(self):
        assert "FAIL" in self._format()

    def test_summary_fail_count_correct(self):
        assert "fail=1" in self._format()

    def test_admit_n_because_not_admitted(self):
        assert "admit=N" in self._format()

    def test_error_message_shown(self):
        assert "worker returned HTTP 401" in self._format()

    def test_attestation_failed_status_shown(self):
        assert "attestation_failed" in self._format()

    def test_ok_zeros_counts_are_zero(self):
        text = self._format()
        assert "ok=0" in text
        assert "zeros=0" in text


# ---------------------------------------------------------------------------
# _format_run_pretty: mixed outcomes
# ---------------------------------------------------------------------------


def test_mixed_outcomes_all_indicators_present():
    run = _make_run([_ok_outcome(), _zero_outcome(), _fail_outcome()])
    buf = io.StringIO()
    _format_run_pretty(run, out=buf)
    text = buf.getvalue()

    assert "OK  " in text
    assert "ZERO" in text
    assert "FAIL" in text
    assert "ok=1" in text
    assert "zeros=1" in text
    assert "fail=1" in text


def test_empty_worker_list_produces_valid_summary():
    run = _make_run([])
    buf = io.StringIO()
    _format_run_pretty(run, out=buf)
    text = buf.getvalue()

    assert "EPOCH START" in text
    assert "EPOCH END" in text
    assert "workers=0" in text
    assert "ok=0" in text


# ---------------------------------------------------------------------------
# _format_run_pretty: failed epoch status flag
# ---------------------------------------------------------------------------


def test_aborted_epoch_shows_failed_flag():
    run = _make_run([], status="aborted")
    buf = io.StringIO()
    _format_run_pretty(run, out=buf)
    assert "!! EPOCH FAILED" in buf.getvalue()


def test_complete_epoch_has_no_failed_flag():
    run = _make_run([_ok_outcome()], status="complete")
    buf = io.StringIO()
    _format_run_pretty(run, out=buf)
    assert "EPOCH FAILED" not in buf.getvalue()


# ---------------------------------------------------------------------------
# _format_publish_pretty
# ---------------------------------------------------------------------------


def test_format_publish_pretty_shows_epoch_and_ok():
    buf = io.StringIO()
    _format_publish_pretty(42, {"status": "accepted"}, out=buf)
    text = buf.getvalue()
    assert "epoch=42" in text
    assert "ok" in text
    assert "accepted" in text


def test_format_publish_pretty_timestamp_present():
    buf = io.StringIO()
    _format_publish_pretty(1, {"status": "accepted"}, out=buf)
    assert _TIMESTAMP_RE.search(buf.getvalue())


def test_format_publish_pretty_uses_publish_label():
    buf = io.StringIO()
    _format_publish_pretty(7, {"status": "accepted"}, out=buf)
    assert "PUBLISH" in buf.getvalue()


# ---------------------------------------------------------------------------
# no bearer / token leakage
# ---------------------------------------------------------------------------


class TestNoTokenLeakage:

    def test_miner_target_repr_excludes_bearer_token(self):
        """MinerTarget.bearer_token is repr=False and must not surface in str()."""
        secret = "super-secret-bearer-token-xyzABC123"
        target = MinerTarget("miner", "https://1.1.1.1", secret)
        assert secret not in repr(target)
        assert secret not in str(target)

    def test_format_run_pretty_does_not_contain_bearer_value(self):
        """EpochRun and MinerOutcome carry no token field; formatted output is clean."""
        secret = "my-bearer-secret-789xyzQRS"
        # Build a realistic run -- token is never stored in outcome/run
        run = _make_run([_ok_outcome(), _fail_outcome()])
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        assert secret not in buf.getvalue()

    def test_format_publish_pretty_does_not_contain_bearer_value(self):
        secret = "hmac-secret-or-bearer-qrs456"
        buf = io.StringIO()
        _format_publish_pretty(1, {"status": "accepted"}, out=buf)
        assert secret not in buf.getvalue()

    def test_bearer_validation_error_does_not_echo_token_value(self):
        """_validate_bearer_token raises with a format description, not the value."""
        from cathedral.runtime import _validate_bearer_token

        # Token that is too long
        long_token = "t" * (MAX_BEARER_TOKEN_LENGTH + 1)
        with pytest.raises(ValueError) as exc_info:
            _validate_bearer_token(long_token, required=True)
        error_text = str(exc_info.value)
        # Should describe the constraint, not echo the token
        assert long_token not in error_text
        assert "t" * 50 not in error_text

    def test_bearer_validation_error_for_invalid_chars_does_not_echo_value(self):
        """Tokens with control chars: error is about format, not the value."""
        from cathedral.runtime import _validate_bearer_token

        bad_token = "bearer\x00hidden"
        with pytest.raises(ValueError) as exc_info:
            _validate_bearer_token(bad_token, required=True)
        assert bad_token not in str(exc_info.value)

    def test_sanitize_error_does_not_introduce_tokens(self):
        """_sanitize_error only strips/truncates; it does not add sensitive text."""
        secret = "some-leaked-value"
        clean_error = "worker returned HTTP 401"
        result = _sanitize_error(clean_error)
        assert secret not in result

    def test_outcome_error_field_is_sanitized_in_pretty_output(self):
        """Error messages with newlines or excess length are cleaned before printing."""
        nasty_error = "line one\nline two\r\nline three " + "x" * 200
        outcome = MinerOutcome(
            hotkey=LONG_HOTKEY,
            endpoint_url="https://1.1.1.1",
            status="sat_failed",
            admitted=True,
            challenge_id=CHALLENGE_ID,
            work_units=0.0,
            score=0.0,
            error=nasty_error,
        )
        run = _make_run([outcome])
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        text = buf.getvalue()
        assert "\n\n" not in text  # newlines inside error must not create blank lines
        # Each line should have a timestamp
        for line in text.strip().splitlines():
            assert _TIMESTAMP_RE.match(line), f"no timestamp on: {line!r}"


# ---------------------------------------------------------------------------
# _sanitize_error: credential redaction
# ---------------------------------------------------------------------------


class TestCredentialRedaction:
    """_sanitize_error must scrub credential values; preserve non-secret text."""

    def test_bearer_assignment_value_redacted(self):
        result = _sanitize_error("bearer=sk-abc123XYZ other context")
        assert "sk-abc123XYZ" not in result
        assert "[REDACTED]" in result

    def test_bearer_colon_assignment_value_redacted(self):
        result = _sanitize_error("bearer: sk-abc123XYZ other context")
        assert "sk-abc123XYZ" not in result
        assert "[REDACTED]" in result

    def test_token_assignment_value_redacted(self):
        result = _sanitize_error("upstream error: token=eyJhbGciOiJSUzI1NiJ9")
        assert "eyJhbGciOiJSUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_secret_assignment_value_redacted(self):
        result = _sanitize_error("secret=hunter2-xYz987 validation failed")
        assert "hunter2-xYz987" not in result
        assert "[REDACTED]" in result

    def test_hmac_assignment_value_redacted(self):
        result = _sanitize_error("hmac=sha256-abc999dead validation failed")
        assert "sha256-abc999dead" not in result
        assert "[REDACTED]" in result

    def test_api_key_underscore_assignment_value_redacted(self):
        result = _sanitize_error("api_key=MY_REAL_API_KEY_XYZ connection refused")
        assert "MY_REAL_API_KEY_XYZ" not in result
        assert "[REDACTED]" in result

    def test_api_key_dash_assignment_value_redacted(self):
        result = _sanitize_error("api-key=real-secret-abc123 timeout")
        assert "real-secret-abc123" not in result
        assert "[REDACTED]" in result

    def test_apikey_no_separator_assignment_value_redacted(self):
        result = _sanitize_error("apikey=plain-secret-789 bad request")
        assert "plain-secret-789" not in result
        assert "[REDACTED]" in result

    def test_authorization_bearer_header_value_redacted(self):
        result = _sanitize_error(
            "upstream returned 401: Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        )
        assert "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "[REDACTED]" in result

    def test_authorization_bearer_case_insensitive(self):
        result = _sanitize_error("AUTHORIZATION: BEARER secret-token-ABC")
        assert "secret-token-ABC" not in result
        assert "[REDACTED]" in result

    def test_nonsecret_error_text_preserved(self):
        # The HTTP status and URL are useful debugging info; must survive.
        result = _sanitize_error("HTTP 503 from https://worker.example.com/attest")
        assert "HTTP 503" in result
        assert "https://worker.example.com/attest" in result

    def test_error_with_secret_preserves_surrounding_text(self):
        result = _sanitize_error("worker returned HTTP 401 token=leaked-value-999 please retry")
        assert "worker returned HTTP 401" in result
        assert "leaked-value-999" not in result
        assert "[REDACTED]" in result

    def test_redaction_runs_before_truncation(self):
        # Construct a string where the credential value spans the truncation
        # boundary at maxlen=100. Without pre-truncation redaction the value
        # would survive partially in the output.
        prefix = "err: token="  # 11 chars
        # Put a 20-char secret starting at position 11; with maxlen=20 the
        # first 9 chars of the secret would survive if we truncated first.
        secret = "TOPSECRET1234567890"
        padding = "x" * 60  # push secret near the boundary
        err = prefix + secret + padding
        result = _sanitize_error(err, maxlen=len(prefix) + 15)
        assert secret[:9] not in result
        assert "[REDACTED]" in result

    def test_no_credential_keywords_no_false_positive(self):
        # A plain error that happens to contain letters like 'key' in a word.
        result = _sanitize_error("monkey returned response with keystroke error")
        # Should not be redacted -- 'monkey' and 'keystroke' are not keyword=
        assert "[REDACTED]" not in result

    def test_multiple_credentials_in_one_error_all_redacted(self):
        result = _sanitize_error(
            "token=tok1 and secret=sec2 caused failure",
            maxlen=200,
        )
        assert "tok1" not in result
        assert "sec2" not in result
        assert result.count("[REDACTED]") >= 2


# ---------------------------------------------------------------------------
# End-to-end: secrets in MinerOutcome.error must not appear in pretty output
# ---------------------------------------------------------------------------


class TestPrettyOutputDoesNotLeakSecrets:
    """Secrets embedded in MinerOutcome.error must not appear in _format_run_pretty output."""

    def _run_with_error(self, error: str) -> str:
        outcome = MinerOutcome(
            hotkey=LONG_HOTKEY,
            endpoint_url="https://9.9.9.9:9001",
            status="attestation_failed",
            admitted=False,
            work_units=0.0,
            score=0.0,
            error=error,
        )
        run = _make_run([outcome])
        buf = io.StringIO()
        _format_run_pretty(run, out=buf)
        return buf.getvalue()

    def test_bearer_token_in_error_not_in_output(self):
        secret = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9SECRETPART"
        text = self._run_with_error(f"upstream 401: bearer={secret}")
        assert secret not in text
        assert "[REDACTED]" in text

    def test_token_value_in_error_not_in_output(self):
        secret = "real-api-token-qrst9876"
        text = self._run_with_error(f"connection refused: token={secret}")
        assert secret not in text
        assert "[REDACTED]" in text

    def test_authorization_bearer_in_error_not_in_output(self):
        secret = "Bearer-header-value-ABCXYZ"
        text = self._run_with_error(f"echo: Authorization: Bearer {secret} end")
        assert secret not in text
        assert "[REDACTED]" in text

    def test_secret_in_error_not_in_output(self):
        secret = "hmac-signature-xyzDEFGHI"
        text = self._run_with_error(f"hmac verification failed: hmac={secret}")
        assert secret not in text
        assert "[REDACTED]" in text

    def test_nonsecret_error_context_preserved_in_output(self):
        # The diagnostic context (HTTP 503, URL) should survive redaction.
        text = self._run_with_error(
            "HTTP 503 from https://miner.example.com/attest token=dropleak"
        )
        assert "HTTP 503" in text
        assert "dropleak" not in text

    def test_multiline_error_with_secret_not_in_output(self):
        # Newlines in upstream errors should be flattened and secrets stripped.
        secret = "multiline-secret-ABC123"
        text = self._run_with_error(f"line one\nAuthorization: Bearer {secret}\nline three")
        assert secret not in text
        assert "[REDACTED]" in text
        # Newlines in the error must not create extra blank lines in output.
        assert "\n\n" not in text


# ---------------------------------------------------------------------------
# CLI parser: --pretty flag
# ---------------------------------------------------------------------------


_RUN_EPOCH_ARGV = [
    "runtime",
    "run-epoch",
    "--registry-db",
    "r.sqlite",
    "--ledger-db",
    "l.sqlite",
    "--measurements-file",
    "m.json",
    "--canary-hotkey",
    "canary",
    "--canary-endpoint",
    "https://8.8.8.8",
    "--source-epoch",
    "7",
]

_RETRY_PUBLISH_ARGV = [
    "runtime",
    "retry-publish",
    "--ledger-db",
    "l.sqlite",
    "--publisher-endpoint",
    "https://example.com/v1/external-scores/violet",
    "--epoch-id",
    "1",
]


def test_run_epoch_pretty_flag_defaults_to_false():
    args = build_parser().parse_args(_RUN_EPOCH_ARGV)
    assert args.pretty is False


def test_run_epoch_pretty_flag_set_when_passed():
    args = build_parser().parse_args([*_RUN_EPOCH_ARGV, "--pretty"])
    assert args.pretty is True


def test_run_epoch_publish_unaffected_by_pretty():
    args = build_parser().parse_args([*_RUN_EPOCH_ARGV, "--pretty"])
    assert args.publish is False
    args2 = build_parser().parse_args([*_RUN_EPOCH_ARGV, "--pretty", "--publish"])
    assert args2.publish is True


def test_retry_publish_pretty_flag_defaults_to_false():
    args = build_parser().parse_args(_RETRY_PUBLISH_ARGV)
    assert args.pretty is False


def test_retry_publish_pretty_flag_set_when_passed():
    args = build_parser().parse_args([*_RETRY_PUBLISH_ARGV, "--pretty"])
    assert args.pretty is True


def test_pretty_flag_not_in_census_subcommand():
    """--pretty is a runtime-specific flag; census should not have it."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["census", "--pretty"])


def test_json_is_default_mode_for_run_epoch(monkeypatch, capsys, tmp_path):
    """Without --pretty, cmd_runtime_run_epoch prints valid JSON to stdout."""
    import argparse

    from cathedral.cli import cmd_runtime_run_epoch
    from cathedral.runtime import ConfidentialRuntime

    fixed_run = _make_run([_ok_outcome()])
    monkeypatch.setattr(
        ConfidentialRuntime, "run_epoch", lambda *a, **kw: fixed_run
    )

    measurements = tmp_path / "m.json"
    measurements.write_text('["measurement"]')

    args = argparse.Namespace(
        registry_db=str(tmp_path / "r.sqlite"),
        ledger_db=str(tmp_path / "l.sqlite"),
        measurements_file=str(measurements),
        tokens_file=None,
        miner_timeout_seconds=10.0,
        miner_attempts=2,
        max_workers=4,
        development=True,
        publisher_endpoint=None,
        publisher_bearer_env="CATHEDRAL_PUBLISHER_BEARER_TOKEN",
        publisher_hmac_env="CATHEDRAL_PUBLISHER_HMAC_SECRET",
        canary_hotkey="canary",
        canary_endpoint="http://127.0.0.1:9000",
        source_epoch=7,
        publish=False,
        pretty=False,
    )
    rc = cmd_runtime_run_epoch(args)
    assert rc == 0
    out = capsys.readouterr().out
    parsed = __import__("json").loads(out)
    assert "epoch_id" in parsed
    assert "outcomes" in parsed


def test_pretty_mode_for_run_epoch_produces_no_json(monkeypatch, capsys, tmp_path):
    """With --pretty, cmd_runtime_run_epoch prints ASCII, not JSON."""
    import argparse

    from cathedral.cli import cmd_runtime_run_epoch
    from cathedral.runtime import ConfidentialRuntime

    fixed_run = _make_run([_ok_outcome()])
    monkeypatch.setattr(
        ConfidentialRuntime, "run_epoch", lambda *a, **kw: fixed_run
    )

    measurements = tmp_path / "m.json"
    measurements.write_text('["measurement"]')

    args = argparse.Namespace(
        registry_db=str(tmp_path / "r.sqlite"),
        ledger_db=str(tmp_path / "l.sqlite"),
        measurements_file=str(measurements),
        tokens_file=None,
        miner_timeout_seconds=10.0,
        miner_attempts=2,
        max_workers=4,
        development=True,
        publisher_endpoint=None,
        publisher_bearer_env="CATHEDRAL_PUBLISHER_BEARER_TOKEN",
        publisher_hmac_env="CATHEDRAL_PUBLISHER_HMAC_SECRET",
        canary_hotkey="canary",
        canary_endpoint="http://127.0.0.1:9000",
        source_epoch=7,
        publish=False,
        pretty=True,
    )
    rc = cmd_runtime_run_epoch(args)
    assert rc == 0
    out = capsys.readouterr().out
    # Should not be parseable as JSON
    with pytest.raises(Exception):
        __import__("json").loads(out)
    assert "EPOCH START" in out
    assert "EPOCH END" in out
    assert "OK  " in out
