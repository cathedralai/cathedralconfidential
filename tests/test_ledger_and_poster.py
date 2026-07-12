from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from cathedral.ledger import Ledger, LedgerError
from cathedral.poster import Poster, PosterError


def attest(ledger: Ledger, epoch_id: int, hotkey: str) -> None:
    ledger.add_attestation(
        epoch_id,
        hotkey,
        verdict="VERIFIED",
        tee_type="TDX",
        workload="CPU",
        evidence_digest=f"evidence-{hotkey}",
    )


def verified_work(
    ledger: Ledger, epoch_id: int, challenge_id: str, hotkey: str, units: float
) -> None:
    ledger.issue_challenge(challenge_id, hotkey, epoch_id)
    ledger.resolve_challenge(
        challenge_id, "verified", units, validator_derived=True
    )


def complete_and_publish(
    ledger: Ledger,
    source_epoch: int,
    work: dict[str, float],
    hotkeys: set[str],
) -> int:
    epoch_id = ledger.begin_epoch(source_epoch)
    for index, (hotkey, units) in enumerate(work.items()):
        verified_work(ledger, epoch_id, f"{source_epoch}-{index}", hotkey, units)
    for hotkey in hotkeys:
        attest(ledger, epoch_id, hotkey)
    ledger.complete_epoch(epoch_id, hotkeys, generated_at=f"2026-01-{source_epoch:02d}T00:00:00Z")
    ledger.mark_published(epoch_id)
    return epoch_id


def report(ledger: Ledger, epoch_id: int) -> dict:
    return json.loads(ledger.report_bytes(epoch_id))


def scores_by_hotkey(payload: dict) -> dict[str, float]:
    return {row["miner_hotkey"]: row["score"] for row in payload["scores"]}


class TestEpochStateMachine:
    def test_memory_ledger_persists_for_lifetime(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        assert ledger.get_epoch(epoch_id)["status"] == "running"
        ledger.complete_epoch(epoch_id, {"hk"})
        assert scores_by_hotkey(report(ledger, epoch_id)) == {"hk": 0.0}

    def test_thread_safe_single_running_epoch(self) -> None:
        ledger = Ledger()
        barrier = threading.Barrier(3)
        outcomes: list[object] = []

        def begin(source_epoch: int) -> None:
            barrier.wait()
            try:
                outcomes.append(ledger.begin_epoch(source_epoch))
            except LedgerError as exc:
                outcomes.append(exc)

        threads = [threading.Thread(target=begin, args=(value,)) for value in (1, 2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        assert sum(isinstance(value, int) for value in outcomes) == 1
        assert sum(isinstance(value, LedgerError) for value in outcomes) == 1

    def test_abort_does_not_consume_source_epoch(self) -> None:
        ledger = Ledger()
        first = ledger.begin_epoch(10)
        ledger.abort_epoch(first)
        with pytest.raises(LedgerError, match="must be retried"):
            ledger.begin_epoch(11)
        retry = ledger.begin_epoch(10)
        assert retry != first
        ledger.complete_epoch(retry, set())
        ledger.mark_published(retry)
        assert ledger.begin_epoch(11)

    def test_completed_snapshot_must_publish_before_next_epoch(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)
        ledger.mark_published(epoch_id)
        assert ledger.begin_epoch(2)

    def test_source_epoch_finalized_uniqueness_and_monotonicity(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(4)
        ledger.complete_epoch(epoch_id, set())
        ledger.mark_published(epoch_id)
        with pytest.raises(LedgerError, match="greater than finalized"):
            ledger.begin_epoch(4)

    def test_crash_reopen_preserves_frozen_report(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.sqlite3"
        first = Ledger(path)
        epoch_id = first.begin_epoch(1)
        verified_work(first, epoch_id, "challenge", "hk", 7)
        attest(first, epoch_id, "hk")
        first.complete_epoch(epoch_id, {"hk"}, generated_at="2026-01-01T00:00:00Z")
        body = first.report_bytes(epoch_id)
        digest = first.report_digest(epoch_id)
        first.close()

        reopened = Ledger(path)
        assert reopened.report_bytes(epoch_id) == body
        assert reopened.report_digest(epoch_id) == digest
        reopened.mark_published(epoch_id, digest)
        assert reopened.get_epoch(epoch_id)["status"] == "published"


class TestEvidenceAndResolution:
    @pytest.mark.parametrize(
        ("verdict", "tee_type", "workload"),
        [
            ("verified", "TDX", "CPU"),
            ("VERIFIED", "SNP", "CPU"),
            ("VERIFIED", "TDX", "GPU"),
        ],
    )
    def test_only_exact_verified_tdx_cpu_attestation(
        self, verdict: str, tee_type: str, workload: str
    ) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        with pytest.raises(LedgerError, match="exact VERIFIED TDX CPU"):
            ledger.add_attestation(
                epoch_id,
                "hk",
                verdict=verdict,
                tee_type=tee_type,
                workload=workload,
                evidence_digest="digest",
            )

    def test_attestation_only_while_running_and_is_immutable(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        attest(ledger, epoch_id, "hk")
        with pytest.raises(LedgerError, match="immutable"):
            ledger.add_attestation(
                epoch_id,
                "hk",
                verdict="VERIFIED",
                tee_type="TDX",
                workload="CPU",
                evidence_digest="changed",
            )
        ledger.complete_epoch(epoch_id, {"hk"})
        with pytest.raises(LedgerError, match="cannot add attestations"):
            attest(ledger, epoch_id, "other")

    @pytest.mark.parametrize("units", [-1, float("nan"), float("inf"), float("-inf")])
    def test_verified_work_must_be_finite_nonnegative(self, units: float) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="finite and nonnegative"):
            ledger.resolve_challenge(
                "challenge", "verified", units, validator_derived=True
            )

    def test_verified_work_must_be_validator_derived(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="validator-derived"):
            ledger.resolve_challenge("challenge", "verified", 10)

    @pytest.mark.parametrize("status", ["failed", "abandoned"])
    def test_failed_and_abandoned_force_zero(self, status: str) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        attest(ledger, epoch_id, "hk")
        ledger.issue_challenge("challenge", "hk", epoch_id)
        ledger.resolve_challenge("challenge", status, 999)
        scores = ledger.complete_epoch(epoch_id, {"hk"})
        assert scores == {"hk": 0.0}

    def test_resolve_only_while_running(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        ledger.abort_epoch(epoch_id)
        with pytest.raises(LedgerError, match="only be resolved"):
            ledger.resolve_challenge("challenge", "failed")

    def test_complete_rejects_unresolved_challenges(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.issue_challenge("challenge", "hk", epoch_id)
        with pytest.raises(LedgerError, match="unresolved issued"):
            ledger.complete_epoch(epoch_id, {"hk"})


class TestReportSnapshot:
    def test_full_universe_zero_revocation_fresh_gate_and_max_normalization(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        verified_work(ledger, epoch_id, "a", "leader", 20)
        verified_work(ledger, epoch_id, "b", "half", 10)
        verified_work(ledger, epoch_id, "c", "stale", 50)
        attest(ledger, epoch_id, "leader")
        attest(ledger, epoch_id, "half")
        attest(ledger, epoch_id, "idle")

        scores = ledger.complete_epoch(
            epoch_id,
            {"leader", "half", "stale", "idle", "enrolled"},
            generated_at="2026-01-01T00:00:00Z",
        )
        assert scores == {
            "leader": 1.0,
            "half": 0.5,
            "stale": 0.0,
            "idle": 0.0,
            "enrolled": 0.0,
        }
        assert all(0 <= value <= 1 for value in scores.values())

    def test_only_published_previous_epochs_enter_trailing_window(self) -> None:
        ledger = Ledger(window_size=3)
        complete_and_publish(ledger, 1, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 2, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 3, {"old": 100}, {"old", "new"})
        complete_and_publish(ledger, 4, {"old": 1000}, {"old", "new"})

        current = ledger.begin_epoch(5)
        verified_work(ledger, current, "current", "new", 300)
        attest(ledger, current, "old")
        attest(ledger, current, "new")
        scores = ledger.complete_epoch(current, {"old", "new"})

        # Epoch 1 fell out; epochs 2-4 plus current are used.
        assert scores == {"old": 1.0, "new": 300 / 1200}
        assert report(ledger, current)["metadata"]["published_window_epochs"] == [2, 3, 4]

    def test_unpublished_completed_epoch_cannot_leak_into_window(self) -> None:
        ledger = Ledger()
        prior = ledger.begin_epoch(1)
        verified_work(ledger, prior, "prior", "hk", 100)
        attest(ledger, prior, "hk")
        ledger.complete_epoch(prior, {"hk"})
        with pytest.raises(LedgerError, match="publish it"):
            ledger.begin_epoch(2)

        # An aborted attempt also contributes nothing when the same source epoch is retried.
        ledger.mark_published(prior)
        attempt = ledger.begin_epoch(2)
        verified_work(ledger, attempt, "discarded", "other", 999)
        attest(ledger, attempt, "other")
        ledger.abort_epoch(attempt)
        retry = ledger.begin_epoch(2)
        attest(ledger, retry, "hk")
        attest(ledger, retry, "other")
        scores = ledger.complete_epoch(retry, {"hk", "other"})
        assert scores == {"hk": 1.0, "other": 0.0}

    def test_report_schema_and_exact_byte_idempotency(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(7)
        verified_work(ledger, epoch_id, "challenge", "hk", 3)
        attest(ledger, epoch_id, "hk")
        first_scores = ledger.complete_epoch(
            epoch_id, {"hk"}, generated_at="2026-01-07T12:00:00Z"
        )
        first_body = ledger.report_bytes(epoch_id)
        first_digest = ledger.report_digest(epoch_id)

        second_scores = ledger.complete_epoch(
            epoch_id, {"hk", "mutating-input"}, generated_at="2099-01-01T00:00:00Z"
        )
        assert second_scores == first_scores
        assert ledger.report_bytes(epoch_id) == first_body
        assert ledger.report_digest(epoch_id) == first_digest == hashlib.sha256(first_body).hexdigest()

        payload = json.loads(first_body)
        assert payload["source"] == payload["mechanism"] == "cathedral_confidential_tdx"
        assert payload["epoch"] == 7
        assert payload["complete"] is True
        assert payload["generated_at"] == "2026-01-07T12:00:00Z"
        assert payload["scores"] == [{"miner_hotkey": "hk", "score": 1.0}]
        assert first_body == json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()

    def test_publish_requires_persisted_digest(self) -> None:
        ledger = Ledger()
        epoch_id = ledger.begin_epoch(1)
        ledger.complete_epoch(epoch_id, set())
        with pytest.raises(LedgerError, match="does not match"):
            ledger.mark_published(epoch_id, "wrong")
        ledger.mark_published(epoch_id, ledger.report_digest(epoch_id))
        ledger.mark_published(epoch_id, ledger.report_digest(epoch_id))


class FakeHeaders(dict):
    pass


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class FakeResponse:
    def __init__(
        self,
        chunks: list[bytes | BaseException],
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.chunks = chunks
        self.status = status
        self.headers = FakeHeaders(headers or {})
        self.fp = type("FP", (), {})()
        self.fp.raw = type("Raw", (), {"_sock": FakeSocket()})()

    def getcode(self) -> int:
        return self.status

    def read(self, _: int) -> bytes:
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        pass


def make_poster(**kwargs) -> Poster:
    return Poster(
        "https://publisher.example/v1/external-scores/violet",
        "bearer-token",
        "hmac-secret",
        **kwargs,
    )


class TestPoster:
    def test_requires_https_and_fixed_public_route(self) -> None:
        with pytest.raises(PosterError, match="HTTPS"):
            Poster(
                "http://publisher.example/v1/external-scores/violet",
                "token",
                "secret",
            )
        Poster(
            "http://localhost/v1/external-scores/violet",
            "token",
            "secret",
            allow_http_for_tests=True,
        )
        with pytest.raises(PosterError, match="endpoint path"):
            Poster("https://publisher.example/other", "token", "secret")

    def test_posts_exact_body_with_required_headers_and_signature(self) -> None:
        poster = make_poster()
        body = b'{"complete":true,"epoch":1}'
        response = FakeResponse([b'{"accepted":true}', b""])
        captured = {}

        def open_request(request, *, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return response

        poster._opener.open = open_request
        assert poster.post(body) == {"accepted": True}
        request = captured["request"]
        assert request.data is body
        assert request.get_method() == "POST"
        assert request.get_header("Authorization") == "Bearer bearer-token"
        assert request.get_header("Content-type") == "application/json"
        expected = hmac.new(b"hmac-secret", body, hashlib.sha256).hexdigest()
        assert request.get_header("X-cathedral-external-signature") == expected
        assert captured["timeout"] == poster.connect_timeout
        assert response.fp.raw._sock.timeouts

    def test_retry_posts_same_bytes_without_mutation(self) -> None:
        poster = make_poster()
        body = b'{"scores":[{"miner_hotkey":"hk","score":1.0}]}'
        seen: list[bytes] = []

        def open_request(request, *, timeout):
            seen.append(request.data)
            return FakeResponse([b"{}", b""])

        poster._opener.open = open_request
        poster.post(body)
        poster.post(body)
        assert seen == [body, body]

    def test_redirect_is_refused(self) -> None:
        poster = make_poster()

        def redirect(*args, **kwargs):
            raise urllib.error.HTTPError(
                poster.endpoint, 302, "Found", {"Location": "https://evil.example"}, None
            )

        poster._opener.open = redirect
        with pytest.raises(PosterError, match="redirect refused"):
            poster.post(b"{}")

    def test_connect_and_read_timeout_fail_closed(self) -> None:
        poster = make_poster(connect_timeout=1, read_timeout=2, total_timeout=3)
        poster._opener.open = lambda *args, **kwargs: (_ for _ in ()).throw(
            urllib.error.URLError(socket.timeout("connect timed out"))
        )
        with pytest.raises(PosterError, match="timed out"):
            poster.post(b"{}")

        poster._opener.open = lambda *args, **kwargs: FakeResponse(
            [socket.timeout("read timed out")]
        )
        with pytest.raises(PosterError, match="timed out"):
            poster.post(b"{}")

    def test_total_deadline_is_enforced(self) -> None:
        poster = make_poster(total_timeout=1)
        response = FakeResponse([b"{}", b""])
        poster._opener.open = lambda *args, **kwargs: response
        with patch("cathedral.poster.time.monotonic", side_effect=[10.0, 10.1, 11.1]):
            with pytest.raises(PosterError, match="total request deadline"):
                poster.post(b"{}")

    def test_bounded_response_and_json_object_required(self) -> None:
        poster = make_poster(response_cap_bytes=4)
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"12345"])
        with pytest.raises(PosterError, match="exceeds configured cap"):
            poster.post(b"{}")

        poster = make_poster()
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"[]", b""])
        with pytest.raises(PosterError, match="JSON must be an object"):
            poster.post(b"{}")

    def test_non_2xx_is_rejected(self) -> None:
        poster = make_poster()
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"{}"], status=299)
        assert poster.post(b"{}") == {}
        poster._opener.open = lambda *args, **kwargs: FakeResponse([b"{}"], status=300)
        with pytest.raises(PosterError, match="unexpected HTTP status 300"):
            poster.post(b"{}")

    def test_only_bytes_are_accepted(self) -> None:
        poster = make_poster()
        with pytest.raises(PosterError, match="exact persisted bytes"):
            poster.post({"scores": []})  # type: ignore[arg-type]


def test_ledger_report_is_posted_byte_for_byte() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    verified_work(ledger, epoch_id, "challenge", "hk", 1)
    attest(ledger, epoch_id, "hk")
    ledger.complete_epoch(epoch_id, {"hk"})
    body = ledger.report_bytes(epoch_id)

    poster = make_poster()
    seen: list[bytes] = []

    def open_request(request, *, timeout):
        seen.append(request.data)
        return FakeResponse([b'{"accepted":true}', b""])

    poster._opener.open = open_request
    assert poster.post(body) == {"accepted": True}
    assert seen == [body]
    ledger.mark_published(epoch_id, hashlib.sha256(seen[0]).hexdigest())
