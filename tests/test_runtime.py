"""Focused integration tests for the confidential report runtime."""

from __future__ import annotations

import ast
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier, issue_nonce
from cathedral.enroll import RegistryStore
from cathedral.lanes.sat import SatLane, solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.ledger import Ledger, LedgerError
from cathedral.runtime import ConfidentialRuntime, MinerTarget, RuntimeConfig, RuntimeError


CANARY = MinerTarget("canary", "http://127.0.0.1:9000")


@dataclass
class MinerSpec:
    chip: str
    evidence_failures: int = 0
    sat_failures: int = 0
    invalid_sat: bool = False
    evidence_kind: EvidenceKind = EvidenceKind.TDX


class FakeClient:
    def __init__(self, endpoint: str, hotkey: str, spec: MinerSpec, log: dict[str, list]) -> None:
        self.endpoint = endpoint
        self.hotkey = hotkey
        self.spec = spec
        self.log = log
        self.evidence_calls = 0
        self.sat_calls = 0

    def collect_evidence(self, nonce: bytes) -> Evidence:
        self.log.setdefault(f"nonce:{self.hotkey}", []).append(nonce)
        self.evidence_calls += 1
        if self.evidence_calls <= self.spec.evidence_failures:
            raise OSError("evidence unavailable")
        return Evidence(
            kind=self.spec.evidence_kind,
            quote=f"chip:{self.spec.chip}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
            cert_chain=[b"chain"],
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        self.log.setdefault(f"sat:{self.hotkey}", []).append(item.challenge_id)
        self.sat_calls += 1
        if self.sat_calls <= self.spec.sat_failures:
            raise OSError("SAT unavailable")
        assignment = solve_sat(item.instance)
        assert assignment is not None
        owner = "wrong-owner" if self.spec.invalid_sat else self.hotkey
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=10**300,
            challenge_id=item.challenge_id,
            assigned_hotkey=owner,
        )


class FakeFactory:
    def __init__(self, specs: dict[str, MinerSpec]) -> None:
        self.specs = specs
        self.log: dict[str, list] = {}

    def __call__(self, endpoint: str, hotkey: str, **_kwargs: object) -> FakeClient:
        spec = self.specs.get(endpoint)
        if spec is None:
            raise OSError("unreachable")
        return FakeClient(endpoint, hotkey, spec, self.log)


def verifier(evidence: Evidence, nonce: bytes, _policy: Policy) -> Attested | None:
    assert evidence.nonce == nonce
    chip = evidence.quote.decode().removeprefix("chip:")
    return Attested(Tier.CC_CPU_TDX, chip, "measurement", 1, "VERIFIED")


def make_runtime(
    tmp_path: Path,
    enrollments: list[tuple[str, str]],
    specs: dict[str, MinerSpec],
    *,
    ledger: Ledger | None = None,
    poster: object | None = None,
    attempts: int = 2,
    nonce_factory=None,
) -> tuple[ConfidentialRuntime, Ledger, FakeFactory]:
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    for hotkey, endpoint in enrollments:
        registry.enroll(hotkey, endpoint)
    actual_ledger = ledger or Ledger(tmp_path / "ledger.sqlite")
    factory = FakeFactory(specs)
    runtime = ConfidentialRuntime(
        registry,
        actual_ledger,
        Policy(allowed_measurements={"measurement"}),
        poster,  # type: ignore[arg-type]
        verifier=verifier,
        nonce_factory=nonce_factory or issue_nonce,
        remote_factory=factory,
        config=RuntimeConfig(
            miner_attempts=attempts,
            max_workers=4,
            production_mode=False,
            allow_insecure_http_for_tests=True,
        ),
    )
    return runtime, actual_ledger, factory


def default_specs(**miners: MinerSpec) -> dict[str, MinerSpec]:
    specs = {CANARY.endpoint_url: MinerSpec("canary-chip")}
    for endpoint, spec in miners.items():
        specs[f"http://127.0.0.1:{endpoint}"] = spec
    return specs


def test_canary_failure_creates_no_epoch(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], {})
    with pytest.raises(RuntimeError, match="canary attestation failed"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_endpoint_collision_creates_no_epoch(tmp_path: Path) -> None:
    specs = {CANARY.endpoint_url: MinerSpec("chip")}
    runtime, ledger, _ = make_runtime(tmp_path, [("miner", CANARY.endpoint_url)], specs)
    with pytest.raises(RuntimeError, match="dedicated"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_collision_is_rejected_even_when_enrollment_is_duplicated(tmp_path: Path) -> None:
    specs = {CANARY.endpoint_url: MinerSpec("chip")}
    runtime, ledger, _ = make_runtime(
        tmp_path,
        [("a", CANARY.endpoint_url), ("b", CANARY.endpoint_url + "/")],
        specs,
    )
    with pytest.raises(RuntimeError, match="dedicated"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None


def test_canary_chip_collision_at_distinct_endpoint_creates_no_epoch(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("canary-chip")})
    runtime, ledger, factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
    )
    with pytest.raises(RuntimeError, match="shares the dedicated canary TDX chip"):
        runtime.run_epoch(1, CANARY)
    assert ledger.blocking_epoch() is None
    assert ledger.get_epoch(1) is None
    assert "nonce:miner" in factory.log
    assert "sat:canary" in factory.log
    assert "sat:miner" not in factory.log


def _production_runtime(
    tmp_path: Path,
    *,
    enrolled_token: str | None,
) -> tuple[ConfidentialRuntime, Ledger, FakeFactory]:
    registry = RegistryStore(str(tmp_path / "production-registry.sqlite"))
    registry.enroll("miner", "https://1.1.1.1:9001")
    ledger = Ledger(tmp_path / "production-ledger.sqlite")
    specs = {
        "https://8.8.8.8:9000": MinerSpec("canary-chip"),
        "https://1.1.1.1:9001": MinerSpec("miner-chip"),
    }
    factory = FakeFactory(specs)
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        Policy(allowed_measurements={"measurement"}),
        token_provider=lambda _hotkey: enrolled_token,
        verifier=verifier,
        remote_factory=factory,
        config=RuntimeConfig(production_mode=True),
    )
    return runtime, ledger, factory


def test_production_missing_canary_token_fails_before_network_or_epoch(tmp_path: Path) -> None:
    runtime, ledger, factory = _production_runtime(tmp_path, enrolled_token="miner-token")
    canary = MinerTarget("canary", "https://8.8.8.8:9000")
    with pytest.raises(ValueError, match="bearer token"):
        runtime.run_epoch(1, canary)
    assert factory.log == {}
    assert ledger.blocking_epoch() is None


def test_production_missing_enrollment_token_fails_before_network_or_epoch(
    tmp_path: Path,
) -> None:
    runtime, ledger, factory = _production_runtime(tmp_path, enrolled_token=None)
    canary = MinerTarget("canary", "https://8.8.8.8:9000", "canary-token")
    with pytest.raises(RuntimeError, match="authentication is required"):
        runtime.run_epoch(1, canary)
    assert factory.log == {}
    assert ledger.blocking_epoch() is None


def test_production_authenticated_targets_complete(tmp_path: Path) -> None:
    runtime, _, factory = _production_runtime(tmp_path, enrolled_token="miner-token")
    canary = MinerTarget("canary", "https://8.8.8.8:9000", "canary-token")
    run = runtime.run_epoch(1, canary)
    assert run.status == "complete"
    assert run.scores["miner"] == 1.0
    assert "nonce:canary" in factory.log and "nonce:miner" in factory.log


def test_two_unique_tdx_miners_complete_normalized(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a"), "9002": MinerSpec("b")})
    runtime, _, _ = make_runtime(
        tmp_path,
        [("miner-a", "http://127.0.0.1:9001"), ("miner-b", "http://127.0.0.1:9002")],
        specs,
    )
    run = runtime.run_epoch(7, CANARY)
    assert run.status == "complete"
    assert run.published is False
    assert dict(run.scores) == {"miner-a": 1.0, "miner-b": 1.0}
    assert {outcome.status for outcome in run.outcomes} == {"verified"}
    assert all(outcome.work_units == 20 for outcome in run.outcomes)


def test_registry_write_failure_does_not_abort_epoch(tmp_path: Path) -> None:
    """record_verdict is a best-effort defense-in-depth refresh; the ledger is
    the authoritative admission record. A transient registry write failure (e.g.
    the separate prober process holding the SQLite write lock) must not abort the
    epoch and void every admitted miner's score."""
    specs = default_specs(**{"9001": MinerSpec("a"), "9002": MinerSpec("b")})
    runtime, _, _ = make_runtime(
        tmp_path,
        [("miner-a", "http://127.0.0.1:9001"), ("miner-b", "http://127.0.0.1:9002")],
        specs,
    )

    def boom(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    runtime.registry.record_verdict = boom  # type: ignore[method-assign]

    run = runtime.run_epoch(7, CANARY)

    assert run.status == "complete"
    assert dict(run.scores) == {"miner-a": 1.0, "miner-b": 1.0}
    assert {outcome.status for outcome in run.outcomes} == {"verified"}


def test_duplicate_endpoint_excludes_all_claimants(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("unused")})
    endpoint = "http://127.0.0.1:9001"
    runtime, _, factory = make_runtime(
        tmp_path, [("a", endpoint), ("b", endpoint + "/")], specs
    )
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"a": 0.0, "b": 0.0}
    assert {outcome.status for outcome in run.outcomes} == {"duplicate_endpoint"}
    assert "nonce:a" not in factory.log and "nonce:b" not in factory.log


@pytest.mark.parametrize("order", [("a", "b"), ("b", "a")])
def test_duplicate_chip_excludes_all_independent_of_order(
    tmp_path: Path, order: tuple[str, str]
) -> None:
    endpoints = {"a": "http://127.0.0.1:9001", "b": "http://127.0.0.1:9002"}
    specs = default_specs(**{"9001": MinerSpec("same"), "9002": MinerSpec("same")})
    runtime, ledger, _ = make_runtime(
        tmp_path, [(hotkey, endpoints[hotkey]) for hotkey in order], specs
    )
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"a": 0.0, "b": 0.0}
    assert {outcome.status for outcome in run.outcomes} == {"duplicate_chip"}
    assert ledger.attested_hotkeys(run.epoch_id) == frozenset()


def test_chip_rotation_to_new_hotkey_is_blocked_within_ttl(tmp_path: Path) -> None:
    """A physical chip verified for hotkey "a" in one epoch must not be
    admitted under a different hotkey "b" in a later epoch while the first
    binding is still effective — even though the two hotkeys never attest
    within the same epoch, so the same-epoch duplicate-chip check alone
    cannot see the collision.
    """

    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    registry.enroll("a", "http://127.0.0.1:9001")
    ledger = Ledger(tmp_path / "ledger.sqlite")
    specs = default_specs(**{"9001": MinerSpec("shared-chip")})
    factory = FakeFactory(specs)
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        Policy(allowed_measurements={"measurement"}),
        poster=RecordingPoster(),
        verifier=verifier,
        remote_factory=factory,
        config=RuntimeConfig(
            max_workers=4,
            production_mode=False,
            allow_insecure_http_for_tests=True,
        ),
    )

    first = runtime.run_epoch(1, CANARY, publish=True)
    assert dict(first.scores) == {"a": 1.0}
    assert {outcome.status for outcome in first.outcomes} == {"verified"}
    assert first.published is True

    # "a"'s worker goes offline; the same physical chip now serves "b" at a
    # freshly enrolled endpoint.
    registry.enroll("b", "http://127.0.0.1:9002")
    specs["http://127.0.0.1:9002"] = MinerSpec("shared-chip")
    del specs["http://127.0.0.1:9001"]

    second = runtime.run_epoch(2, CANARY)
    assert dict(second.scores) == {"a": 0.0, "b": 0.0}
    statuses = {outcome.hotkey: outcome.status for outcome in second.outcomes}
    assert statuses["a"] == "attestation_failed"
    assert statuses["b"] == "chip_rotation_conflict"
    assert "already bound to hotkey a" in (
        next(o.error for o in second.outcomes if o.hotkey == "b") or ""
    )


def test_invalid_miner_is_zero_while_peer_succeeds(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("good")})
    runtime, _, _ = make_runtime(
        tmp_path,
        [("bad", "http://127.0.0.1:9999"), ("good", "http://127.0.0.1:9001")],
        specs,
    )
    run = runtime.run_epoch(1, CANARY)
    assert dict(run.scores) == {"bad": 0.0, "good": 1.0}
    assert {outcome.hotkey: outcome.status for outcome in run.outcomes} == {
        "bad": "attestation_failed",
        "good": "verified",
    }


def test_retries_use_fresh_evidence_nonce_and_same_sat_challenge(tmp_path: Path) -> None:
    counter = iter(range(20))

    def nonces() -> bytes:
        return next(counter).to_bytes(32, "big")

    specs = default_specs(**{"9001": MinerSpec("a", evidence_failures=1, sat_failures=1)})
    runtime, _, factory = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        nonce_factory=nonces,
    )
    run = runtime.run_epoch(1, CANARY)
    assert run.scores["miner"] == 1.0
    assert len(set(factory.log["nonce:miner"])) == 2
    assert len(factory.log["sat:miner"]) == 2
    assert len(set(factory.log["sat:miner"])) == 1


def test_exact_owner_rejection_completes_as_zero(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=True)})
    runtime, _, _ = make_runtime(
        tmp_path, [("miner", "http://127.0.0.1:9001")], specs
    )
    run = runtime.run_epoch(1, CANARY)
    assert run.scores["miner"] == 0.0
    assert run.outcomes[0].status == "sat_failed"


def test_runtime_exception_aborts_and_same_source_retries(tmp_path: Path, monkeypatch) -> None:
    specs = default_specs(**{"9001": MinerSpec("a")})
    runtime, ledger, _ = make_runtime(
        tmp_path, [("miner", "http://127.0.0.1:9001")], specs
    )
    original = ledger.complete_epoch

    def explode(*_args, **_kwargs):
        raise RuntimeError("freeze failed")

    monkeypatch.setattr(ledger, "complete_epoch", explode)
    with pytest.raises(RuntimeError, match="freeze failed"):
        runtime.run_epoch(3, CANARY)
    assert ledger.get_epoch(1)["status"] == "aborted"

    monkeypatch.setattr(ledger, "complete_epoch", original)
    retried = runtime.run_epoch(3, CANARY)
    assert retried.status == "complete"
    assert retried.source_epoch == 3


def test_unresolved_challenge_cannot_complete() -> None:
    ledger = Ledger()
    epoch_id = ledger.begin_epoch(1)
    ledger.issue_challenge("challenge", "miner", epoch_id)
    with pytest.raises(LedgerError, match="unresolved"):
        ledger.complete_epoch(epoch_id, {"miner"})


@pytest.mark.parametrize("enrollments", [[], [("miner", "http://127.0.0.1:9001")]])
def test_empty_and_healthy_no_work_snapshots_complete(
    tmp_path: Path, enrollments: list[tuple[str, str]]
) -> None:
    specs = default_specs(**{"9001": MinerSpec("a", invalid_sat=True)})
    runtime, ledger, _ = make_runtime(tmp_path, enrollments, specs)
    run = runtime.run_epoch(1, CANARY)
    assert run.status == "complete"
    assert all(score == 0 for score in run.scores.values())
    assert b'"complete":true' in ledger.report_bytes(run.epoch_id)


class RecordingPoster:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.bodies: list[bytes] = []

    def post(self, body: bytes) -> dict[str, str]:
        self.bodies.append(body)
        if self.fail:
            raise OSError("ambiguous publication failure")
        return {"status": "accepted"}


def test_dry_run_publish_failure_and_byte_identical_retry(tmp_path: Path) -> None:
    specs = default_specs(**{"9001": MinerSpec("a")})
    poster = RecordingPoster(fail=True)
    runtime, ledger, _ = make_runtime(
        tmp_path,
        [("miner", "http://127.0.0.1:9001")],
        specs,
        poster=poster,
    )
    run = runtime.run_epoch(1, CANARY)
    assert poster.bodies == []

    with pytest.raises(OSError, match="ambiguous"):
        runtime.publish_completed(run.epoch_id)
    assert ledger.get_epoch(run.epoch_id)["status"] == "complete"
    frozen = ledger.report_bytes(run.epoch_id)

    poster.fail = False
    runtime.publish_completed(run.epoch_id)
    assert ledger.get_epoch(run.epoch_id)["status"] == "published"
    assert poster.bodies == [frozen, frozen]
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.publish_completed(run.epoch_id)


def test_restart_status_and_explicit_abort(tmp_path: Path) -> None:
    db = tmp_path / "ledger.sqlite"
    first = Ledger(db)
    epoch_id = first.begin_epoch(9)
    first.close()
    runtime, reopened, _ = make_runtime(tmp_path, [], default_specs(), ledger=Ledger(db))
    assert runtime.status()["blocking_epoch"]["status"] == "running"
    assert runtime.abort_running() == epoch_id
    assert reopened.get_epoch(epoch_id)["status"] == "aborted"


def test_abandon_completed_unblocks_begin_epoch_and_is_audited(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], default_specs())
    run = runtime.run_epoch(1, CANARY)
    assert run.status == "complete"

    with pytest.raises(LedgerError, match="publish it"):
        ledger.begin_epoch(2)

    epoch_id = runtime.abandon_completed(run.epoch_id, "report too old for first ingest")
    assert epoch_id == run.epoch_id
    row = ledger.get_epoch(epoch_id)
    assert row["status"] == "abandoned"
    assert row["abandon_reason"] == "report too old for first ingest"
    assert row["abandoned_at"] is not None

    # begin_epoch is unblocked; a later source epoch can proceed.
    next_run = runtime.run_epoch(2, CANARY)
    assert next_run.status == "complete"


def test_abandon_completed_requires_exact_blocking_epoch(tmp_path: Path) -> None:
    runtime, ledger, _ = make_runtime(tmp_path, [], default_specs())
    run = runtime.run_epoch(1, CANARY)
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.abandon_completed(run.epoch_id + 1, "reason")


def test_abandon_completed_rejects_a_running_epoch(tmp_path: Path) -> None:
    db = tmp_path / "ledger.sqlite"
    first = Ledger(db)
    epoch_id = first.begin_epoch(1)
    first.close()
    runtime, _, _ = make_runtime(tmp_path, [], default_specs(), ledger=Ledger(db))
    with pytest.raises(RuntimeError, match="exact completed"):
        runtime.abandon_completed(epoch_id, "reason")


def test_runtime_has_no_forbidden_scorer_path_imports_or_calls() -> None:
    path = Path(__file__).parents[1] / "cathedral" / "runtime.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {"attested_epoch", "apply_routing", "bittensor", "set_weights"}
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").lower())
            imported.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id.lower())
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr.lower())
    assert not any(any(name in value for name in forbidden) for value in imported)
    assert forbidden.isdisjoint(called)


def test_sat_lane_still_rejects_wrong_owner() -> None:
    lane = SatLane(namespace="owner-test")
    item = lane.dispatch("expected", 1)
    assert isinstance(item, SatWorkItem)
    cert = SatCertificate(
        True,
        solve_sat(item.instance),
        20,
        item.challenge_id,
        "other",
    )
    assert lane.verify(item, cert) is None
