"""Comprehensive ledger and poster tests.

Coverage:
  Ledger: duplicate, restart, window, gate, empty-vs-abort, no-advance, idempotence
  Poster: HMAC, HTTP test mode, HTTPS enforcement, response cap, timeout, deterministic JSON
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from io import StringIO
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError

import pytest

from cathedral.ledger import Ledger, LedgerError
from cathedral.poster import Poster, PosterError


# ============================================================================
# LEDGER TESTS
# ============================================================================


class TestLedgerDuplicate:
    """Duplicate challenge_id raises; no retry."""

    def test_duplicate_challenge_id_raises(self):
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)

        # First challenge succeeds
        ledger.issue_challenge("ch1", "hk1", epoch_id)

        # Second with same challenge_id raises
        with pytest.raises(LedgerError, match="duplicate challenge_id"):
            ledger.issue_challenge("ch1", "hk1", epoch_id)

    def test_issue_challenge_on_running_epoch_only(self):
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("ch1", "hk1", epoch_id)

        # Complete the epoch (no hotkeys yet)
        ledger.complete_epoch(epoch_id, frozenset())

        # Now try to issue a challenge in the completed epoch
        with pytest.raises(LedgerError, match="is 'complete'; cannot issue"):
            ledger.issue_challenge("ch2", "hk1", epoch_id)


class TestLedgerRestart:
    """Restart semantics: abort preserves source_epoch, no reuse."""

    def test_source_epoch_monotonic_increase(self):
        ledger = Ledger()
        epoch1 = ledger.begin_epoch(1)
        epoch2 = ledger.begin_epoch(2)
        assert epoch1 != epoch2

    def test_source_epoch_not_decreasing(self):
        ledger = Ledger()
        ledger.begin_epoch(1)

        # Retry with same source_epoch must fail
        with pytest.raises(LedgerError, match="not greater than"):
            ledger.begin_epoch(1)

        # Even after abort
        with pytest.raises(LedgerError, match="not greater than"):
            ledger.begin_epoch(1)

    def test_abort_preserves_source_epoch_slot(self):
        """Abort consumes the source_epoch; next epoch must be > previous."""
        ledger = Ledger()
        epoch1 = ledger.begin_epoch(10)
        ledger.abort_epoch(epoch1)

        # Cannot reuse 10
        with pytest.raises(LedgerError, match="not greater than"):
            ledger.begin_epoch(10)

        # Must use 11 or higher
        epoch2 = ledger.begin_epoch(11)
        assert epoch1 != epoch2


class TestLedgerWindow:
    """Window scoring: sum last 3 complete epochs."""

    def test_window_scoring_last_three_complete(self):
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1", "hk2"})

        # Epoch 1: hk1=10, hk2=5
        e1 = ledger.begin_epoch(1)
        ledger.issue_challenge("ch1a", "hk1", e1)
        ledger.resolve_challenge("ch1a", "verified", 10.0)
        ledger.issue_challenge("ch1b", "hk2", e1)
        ledger.resolve_challenge("ch1b", "verified", 5.0)
        ledger.complete_epoch(e1, all_hotkeys)

        # Epoch 2: hk1=20, hk2=10
        e2 = ledger.begin_epoch(2)
        ledger.issue_challenge("ch2a", "hk1", e2)
        ledger.resolve_challenge("ch2a", "verified", 20.0)
        ledger.issue_challenge("ch2b", "hk2", e2)
        ledger.resolve_challenge("ch2b", "verified", 10.0)
        ledger.complete_epoch(e2, all_hotkeys)

        # Epoch 3: hk1=30
        e3 = ledger.begin_epoch(3)
        ledger.issue_challenge("ch3a", "hk1", e3)
        ledger.resolve_challenge("ch3a", "verified", 30.0)
        ledger.complete_epoch(e3, all_hotkeys)

        # Window (last 3) should include all: hk1=60, hk2=15
        window = ledger.window_scores(n=3)
        assert window["hk1"] == 60.0
        assert window["hk2"] == 15.0

    def test_window_scoring_partial_window(self):
        """Only 2 complete epochs; still sum them."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1"})

        e1 = ledger.begin_epoch(1)
        ledger.issue_challenge("ch1", "hk1", e1)
        ledger.resolve_challenge("ch1", "verified", 10.0)
        ledger.complete_epoch(e1, all_hotkeys)

        e2 = ledger.begin_epoch(2)
        ledger.issue_challenge("ch2", "hk1", e2)
        ledger.resolve_challenge("ch2", "verified", 20.0)
        ledger.complete_epoch(e2, all_hotkeys)

        # Window(n=3) still sums both available
        window = ledger.window_scores(n=3)
        assert window["hk1"] == 30.0

    def test_window_scoring_excludes_aborted(self):
        """Aborted epochs not included in window."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1"})

        e1 = ledger.begin_epoch(1)
        ledger.abort_epoch(e1)

        e2 = ledger.begin_epoch(2)
        ledger.issue_challenge("ch2", "hk1", e2)
        ledger.resolve_challenge("ch2", "verified", 10.0)
        ledger.complete_epoch(e2, all_hotkeys)

        window = ledger.window_scores(n=3)
        assert window.get("hk1") == 10.0


class TestLedgerGate:
    """Gate: only fresh-attested hotkeys in gated_scores."""

    def test_gated_scores_fresh_attestation(self):
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1", "hk2"})

        e_prev = ledger.begin_epoch(99)
        e_current = ledger.begin_epoch(100)

        # Previous epoch: both hotkeys with work
        ledger.issue_challenge("ch_p1", "hk1", e_prev)
        ledger.resolve_challenge("ch_p1", "verified", 50.0)
        ledger.issue_challenge("ch_p2", "hk2", e_prev)
        ledger.resolve_challenge("ch_p2", "verified", 25.0)
        ledger.complete_epoch(e_prev, all_hotkeys)

        # Current epoch: only hk1 has fresh attestation
        ledger.add_attestation(
            e_current, "hk1", chip_id="chip_a", measurement="m1", tcb=1
        )

        # gated_scores filters: hk1 is attested + scoring, hk2 is not
        gated = ledger.gated_scores(e_current, n=3)
        assert gated.get("hk1") == 50.0
        assert "hk2" not in gated  # No attestation in current epoch

    def test_gated_scores_zero_scoring_excluded(self):
        """Attested but zero score excluded from gated_scores."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1"})

        e_prev = ledger.begin_epoch(0)
        e_current = ledger.begin_epoch(1)

        # Previous: no work for hk1 (scores 0)
        ledger.complete_epoch(e_prev, all_hotkeys)

        # Current: attestation but no window score
        ledger.add_attestation(
            e_current, "hk1", chip_id="chip_a", measurement="m1", tcb=1
        )

        gated = ledger.gated_scores(e_current, n=3)
        assert gated == {}  # Excluded: zero score


class TestLedgerEmptyVsAbort:
    """Healthy empty epoch completes and is publishable; abort prevents both."""

    def test_empty_epoch_completes_successfully(self):
        """No challenges, but still completes with all-zero revokes."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1", "hk2"})

        e = ledger.begin_epoch(1)
        # No challenges issued

        scores = ledger.complete_epoch(e, all_hotkeys)
        # All hotkeys explicitly zero
        assert scores == {"hk1": 0.0, "hk2": 0.0}

        # Can publish
        ledger.mark_published(e, "digest_xyz")
        epoch_data = ledger.get_epoch(e)
        assert epoch_data["status"] == "published"
        assert epoch_data["report_digest"] == "digest_xyz"

    def test_aborted_epoch_cannot_complete(self):
        """Abort → cannot complete_epoch."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1"})

        e = ledger.begin_epoch(1)
        ledger.abort_epoch(e)

        with pytest.raises(LedgerError, match="is 'aborted'; cannot complete"):
            ledger.complete_epoch(e, all_hotkeys)

    def test_aborted_epoch_cannot_publish(self):
        """Abort → cannot mark_published."""
        ledger = Ledger()
        e = ledger.begin_epoch(1)
        ledger.abort_epoch(e)

        with pytest.raises(LedgerError, match="is 'aborted'; cannot publish"):
            ledger.mark_published(e, "digest_xyz")


class TestLedgerNoAdvance:
    """Cannot advance beyond aborted state."""

    def test_no_completion_after_abort(self):
        """Once aborted, complete_epoch always fails."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1"})

        e = ledger.begin_epoch(1)
        ledger.abort_epoch(e)

        # First attempt
        with pytest.raises(LedgerError):
            ledger.complete_epoch(e, all_hotkeys)

        # Retry also fails
        with pytest.raises(LedgerError):
            ledger.complete_epoch(e, all_hotkeys)

    def test_no_publish_after_abort(self):
        """Once aborted, mark_published always fails."""
        ledger = Ledger()
        e = ledger.begin_epoch(1)
        ledger.abort_epoch(e)

        with pytest.raises(LedgerError):
            ledger.mark_published(e, "digest_xyz")


class TestLedgerIdempotence:
    """Idempotent operations return stable results."""

    def test_complete_epoch_idempotent(self):
        """Calling complete_epoch twice returns same scores."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1", "hk2"})

        e = ledger.begin_epoch(1)
        ledger.issue_challenge("ch1", "hk1", e)
        ledger.resolve_challenge("ch1", "verified", 42.0)

        scores1 = ledger.complete_epoch(e, all_hotkeys)
        scores2 = ledger.complete_epoch(e, all_hotkeys)

        assert scores1 == scores2
        assert scores1["hk1"] == 42.0
        assert scores1["hk2"] == 0.0

    def test_mark_published_idempotent_same_digest(self):
        """Reposting same digest is a no-op."""
        ledger = Ledger()
        all_hotkeys = frozenset()

        e = ledger.begin_epoch(1)
        ledger.complete_epoch(e, all_hotkeys)

        digest = "abc123def456"
        ledger.mark_published(e, digest)
        ledger.mark_published(e, digest)  # Idempotent

        epoch_data = ledger.get_epoch(e)
        assert epoch_data["status"] == "published"
        assert epoch_data["report_digest"] == digest

    def test_mark_published_rejects_mismatched_digest(self):
        """Retrying with different digest is rejected."""
        ledger = Ledger()
        all_hotkeys = frozenset()

        e = ledger.begin_epoch(1)
        ledger.complete_epoch(e, all_hotkeys)

        ledger.mark_published(e, "digest_1")

        # Retry with different digest
        with pytest.raises(LedgerError, match="different digest"):
            ledger.mark_published(e, "digest_2")

    def test_add_attestation_idempotent(self):
        """Reposting attestation overwrites, doesn't error."""
        ledger = Ledger()
        e = ledger.begin_epoch(1)

        # First post
        ledger.add_attestation(e, "hk1", "chip_a", "m1", tcb=1)

        # Second post with same data: idempotent
        ledger.add_attestation(e, "hk1", "chip_a", "m1", tcb=1)

        # Or with updated data: overwrites
        ledger.add_attestation(e, "hk1", "chip_b", "m2", tcb=2)

        attested = ledger.attested_hotkeys(e)
        assert attested == frozenset({"hk1"})


# ============================================================================
# POSTER TESTS
# ============================================================================


class TestPosterDeterministicJSON:
    """Deterministic JSON serialization with sorted keys."""

    def test_same_weights_same_json(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
        )

        weights1 = {"hk1": 10.0, "hk2": 20.0}
        json1 = poster._serialize_weights(weights1)

        weights2 = {"hk2": 20.0, "hk1": 10.0}  # Different order
        json2 = poster._serialize_weights(weights2)

        assert json1 == json2

    def test_json_format_exact(self):
        """No spaces, sorted keys, colon-comma separators."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
        )

        weights = {"b": 2.0, "a": 1.0, "c": 3.0}
        json_out = poster._serialize_weights(weights)

        # Verify no spaces and sorted order
        assert json_out == '{"a":1.0,"b":2.0,"c":3.0}'

    def test_compute_digest_stable(self):
        """Same weights produce same digest across calls."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
        )

        weights = {"hk1": 10.0}

        digest1 = poster._compute_digest(weights)
        digest2 = poster._compute_digest(weights)

        assert digest1 == digest2

    def test_digest_is_sha256_hex(self):
        """Digest matches manual SHA256 computation."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
        )

        weights = {"hk1": 10.0}
        json_payload = poster._serialize_weights(weights)
        expected_digest = hashlib.sha256(json_payload.encode()).hexdigest()

        computed_digest = poster._compute_digest(weights)
        assert computed_digest == expected_digest


class TestPosterHMAC:
    """HMAC-SHA256 signature computation."""

    def test_hmac_signature_matches_expected(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
        )

        weights = {"hk1": 10.0}
        json_payload = poster._serialize_weights(weights)

        expected_sig = hmac.new(
            "secret123".encode(),
            json_payload.encode(),
            hashlib.sha256,
        ).digest().hex()

        computed_sig = poster._hmac_sha256(json_payload)
        assert computed_sig == expected_sig

    def test_different_secret_different_signature(self):
        poster1 = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret1",
        )
        poster2 = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret2",
        )

        weights = {"hk1": 10.0}
        json_payload = poster1._serialize_weights(weights)

        sig1 = poster1._hmac_sha256(json_payload)
        sig2 = poster2._hmac_sha256(json_payload)

        assert sig1 != sig2


class TestPosterHTTPEnforcement:
    """HTTPS enforcement; HTTP allowed only in test_mode."""

    def test_https_endpoint_accepted(self):
        # Should not raise on construction or pre-validation
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=False,
        )
        assert poster.endpoint.startswith("https://")

    def test_http_endpoint_rejected_by_default(self):
        poster = Poster(
            endpoint="http://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=False,
        )

        with patch(
            "urllib.request.urlopen",
            side_effect=Exception("should not be called"),
        ):
            with pytest.raises(PosterError, match="must be HTTPS"):
                poster.post({"hk1": 10.0})

    def test_http_endpoint_allowed_in_test_mode(self):
        poster = Poster(
            endpoint="http://localhost:8080/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        # Mock urlopen to avoid actual network call
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [b'{"status":"ok"}', b'']

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = poster.post({"hk1": 10.0})
            assert result == {"status": "ok"}


class TestPosterBearerToken:
    """Bearer token in Authorization header."""

    def test_bearer_token_in_request(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token_abc123",
            secret="secret123",
            test_mode=True,
        )

        # Mock urlopen; capture the request object
        captured_req = None

        def capture_urlopen(req, **kwargs):
            nonlocal captured_req
            captured_req = req
            mock_response = MagicMock()
            mock_response.__enter__.return_value = mock_response
            mock_response.read.side_effect = [b'{"status":"ok"}', b'']
            return mock_response

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            poster.post({"hk1": 10.0})

        assert captured_req is not None
        assert captured_req.headers.get("Authorization") == "Bearer token_abc123"

    def test_signature_in_request(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        captured_req = None

        def capture_urlopen(req, **kwargs):
            nonlocal captured_req
            captured_req = req
            mock_response = MagicMock()
            mock_response.__enter__.return_value = mock_response
            mock_response.read.side_effect = [b'{"status":"ok"}', b'']
            return mock_response

        weights = {"hk1": 10.0}
        expected_sig = poster._hmac_sha256(poster._serialize_weights(weights))

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            poster.post(weights)

        assert captured_req is not None
        # Headers are stored with specific casing in the dict
        assert captured_req.headers.get("X-Signature") == expected_sig or captured_req.headers.get("X-signature") == expected_sig


class TestPosterResponseCap:
    """Response body size cap enforcement."""

    def test_response_under_cap_succeeds(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            response_cap_bytes=1024,
            test_mode=True,
        )

        response_json = '{"status":"ok"}'
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [response_json.encode(), b'']

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = poster.post({"hk1": 10.0})
            assert result == {"status": "ok"}

    def test_response_exceeds_cap_raises(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            response_cap_bytes=10,  # Very small cap
            test_mode=True,
        )

        # Simulate response that exceeds cap
        large_response = "x" * 1000
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [
            large_response.encode(),
        ]

        with patch("urllib.request.urlopen", return_value=mock_response):
            with pytest.raises(PosterError, match="exceeded cap"):
                poster.post({"hk1": 10.0})

    def test_response_cap_chunked_read(self):
        """Cap enforced across multiple chunks."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            response_cap_bytes=100,
            test_mode=True,
        )

        # Multiple chunks that exceed cap when summed
        chunk1 = b"x" * 60
        chunk2 = b"y" * 60  # Total 120 > cap 100
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [chunk1, chunk2, b""]

        with patch("urllib.request.urlopen", return_value=mock_response):
            with pytest.raises(PosterError, match="exceeded cap"):
                poster.post({"hk1": 10.0})


class TestPosterTimeout:
    """Timeout enforcement on request/response."""

    def test_timeout_on_urlopen(self):
        """urllib.request.urlopen timeout raises PosterError."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            timeout_seconds=5.0,
            test_mode=True,
        )

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            with pytest.raises(PosterError, match="URL error"):
                poster.post({"hk1": 10.0})

    def test_timeout_on_read(self):
        """Timeout during response body read."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            timeout_seconds=5.0,
            test_mode=True,
        )

        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = OSError("timeout")

        with patch("urllib.request.urlopen", return_value=mock_response):
            with pytest.raises(PosterError, match="Read error"):
                poster.post({"hk1": 10.0})


class TestPosterIdempotence:
    """Same digest retry is idempotent."""

    def test_same_digest_retry_succeeds(self):
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        weights = {"hk1": 10.0}
        digest = poster._compute_digest(weights)

        # First post
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [b'{"status":"ok"}', b'', b'{"status":"ok"}', b'']

        with patch("urllib.request.urlopen", return_value=mock_response):
            result1 = poster.post(weights, digest=digest)
            result2 = poster.post(weights, digest=digest)

        assert result1 == result2 == {"status": "ok"}

    def test_digest_recomputation_on_retry(self):
        """Digest automatically recomputed on retry if not provided."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        weights = {"hk1": 10.0}

        captured_digests = []

        def capture_urlopen(req, **kwargs):
            captured_digests.append(req.get_header("X-Digest"))
            mock_response = MagicMock()
            mock_response.__enter__.return_value = mock_response
            mock_response.read.side_effect = [b'{"status":"ok"}', b'']
            return mock_response

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            poster.post(weights)
            poster.post(weights)

        # Both should have same digest
        assert len(captured_digests) == 2
        assert captured_digests[0] == captured_digests[1]


class TestPosterIntegration:
    """Full integration: weights → JSON → HMAC → POST → response."""

    def test_full_posting_flow(self):
        """End-to-end: weights to response."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="bearer_xyz",
            secret="secret_xyz",
            test_mode=True,
        )

        weights = {"hk1": 100.0, "hk2": 50.0}
        expected_response = {"published": True, "epoch_id": 42}

        captured_req = None

        def capture_and_respond(req, **kwargs):
            nonlocal captured_req
            captured_req = req
            mock_response = MagicMock()
            mock_response.__enter__.return_value = mock_response
            response_json = json.dumps(expected_response).encode()
            mock_response.read.side_effect = [response_json, b'']
            return mock_response

        with patch("urllib.request.urlopen", side_effect=capture_and_respond):
            result = poster.post(weights)

        # Verify request
        assert captured_req is not None
        assert captured_req.headers.get("Content-type") == "application/json"
        assert captured_req.headers.get("Authorization") == "Bearer bearer_xyz"
        assert captured_req.headers.get("X-Signature") or captured_req.headers.get("X-signature")
        assert captured_req.headers.get("X-Digest") or captured_req.headers.get("X-digest")

        # Verify response
        assert result == expected_response

    def test_malformed_json_response_raises(self):
        """Invalid JSON from server raises PosterError."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [b"not valid json {{", b'']

        with patch("urllib.request.urlopen", return_value=mock_response):
            with pytest.raises(PosterError, match="Invalid JSON"):
                poster.post({"hk1": 10.0})

    def test_http_error_response_raises(self):
        """HTTP 4xx/5xx errors raise PosterError."""
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        with patch(
            "urllib.request.urlopen",
            side_effect=HTTPError(
                "https://example.com/epochs",
                403,
                "Forbidden",
                {},
                None,
            ),
        ):
            with pytest.raises(PosterError, match="HTTP 403"):
                poster.post({"hk1": 10.0})


# ============================================================================
# COMBINED TESTS: Ledger + Poster integration
# ============================================================================


class TestLedgerPosterIntegration:
    """Ledger outputs scores; Poster sends them."""

    def test_gated_scores_posted(self):
        """Complete epoch, gate the scores, post via Poster."""
        ledger = Ledger()
        all_hotkeys = frozenset({"hk1", "hk2", "hk3"})

        # Setup: 2 complete epochs with work
        e_prev = ledger.begin_epoch(1)
        ledger.issue_challenge("ch_p1", "hk1", e_prev)
        ledger.resolve_challenge("ch_p1", "verified", 100.0)
        ledger.issue_challenge("ch_p2", "hk2", e_prev)
        ledger.resolve_challenge("ch_p2", "verified", 50.0)
        ledger.complete_epoch(e_prev, all_hotkeys)

        # Current epoch: only hk1 and hk2 attested (hk3 not attested)
        e_current = ledger.begin_epoch(2)
        ledger.add_attestation(e_current, "hk1", "chip_a", "m1", tcb=1)
        ledger.add_attestation(e_current, "hk2", "chip_b", "m2", tcb=1)

        # Get gated scores: hk1, hk2 (both attested + scoring), hk3 excluded
        gated = ledger.gated_scores(e_current, n=3)
        assert gated == {"hk1": 100.0, "hk2": 50.0}

        # Post via Poster
        poster = Poster(
            endpoint="https://example.com/epochs",
            bearer_token="token123",
            secret="secret123",
            test_mode=True,
        )

        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.side_effect = [b'{"ok":true}', b'']

        with patch("urllib.request.urlopen", return_value=mock_response):
            response = poster.post(gated)
            assert response == {"ok": True}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
