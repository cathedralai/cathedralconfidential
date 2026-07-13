"""Confidential TDX report runtime.

This module only freezes and optionally publishes Cathedral confidential-compute
reports. The existing validator remains the sole owner of score composition,
signing, and chain publication.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import urllib.parse
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier, issue_nonce
from cathedral.enroll import RegistryStore
from cathedral.lanes.sat import SatLane
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.poster import Poster
from cathedral.remote import RemoteMiner
from cathedral.verify import verify

MAX_BEARER_TOKEN_LENGTH = 4096


class RuntimeError(Exception):
    """Raised when a confidential runtime invariant fails."""


class MinerClient(Protocol):
    def collect_evidence(self, nonce: bytes) -> Evidence: ...

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate: ...


@dataclass(frozen=True)
class MinerTarget:
    hotkey: str
    endpoint_url: str
    bearer_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RuntimeConfig:
    miner_timeout_seconds: float = 10.0
    miner_attempts: int = 2
    max_workers: int = 8
    production_mode: bool = True
    allow_insecure_http_for_tests: bool = False

    def __post_init__(self) -> None:
        timeout = self.miner_timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("miner_timeout_seconds must be positive and finite")
        if (
            isinstance(self.miner_attempts, bool)
            or not isinstance(self.miner_attempts, int)
            or self.miner_attempts <= 0
        ):
            raise ValueError("miner_attempts must be a positive integer")
        if (
            isinstance(self.max_workers, bool)
            or not isinstance(self.max_workers, int)
            or not 1 <= self.max_workers <= 64
        ):
            raise ValueError("max_workers must be between 1 and 64")
        if not isinstance(self.production_mode, bool):
            raise ValueError("production_mode must be a boolean")
        if not isinstance(self.allow_insecure_http_for_tests, bool):
            raise ValueError("allow_insecure_http_for_tests must be a boolean")
        if self.production_mode and self.allow_insecure_http_for_tests:
            raise ValueError("insecure HTTP is unavailable in production mode")


@dataclass(frozen=True)
class MinerOutcome:
    hotkey: str
    endpoint_url: str
    status: str
    admitted: bool = False
    challenge_id: str | None = None
    work_units: float = 0.0
    score: float = 0.0
    error: str | None = None


@dataclass(frozen=True)
class EpochRun:
    epoch_id: int
    source_epoch: int
    status: str
    outcomes: tuple[MinerOutcome, ...]
    scores: Mapping[str, float]
    published: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "scores", MappingProxyType(dict(self.scores)))


@dataclass(frozen=True)
class _AttestationResult:
    target: MinerTarget
    endpoint: str
    attested: Attested | None = None
    evidence_digest: str | None = None
    client: MinerClient | None = None
    error: str | None = None


@dataclass(frozen=True)
class _CanaryResult:
    outcome: MinerOutcome
    attestation: _AttestationResult


Verifier = Callable[[Evidence, bytes, Policy], Attested | None]
NonceFactory = Callable[[], bytes]
TokenProvider = Callable[[str], str | None]
RemoteFactory = Callable[..., MinerClient]


class ConfidentialRuntime:
    """Run one fresh TDX attestation and one canonical SAT job per enrollment."""

    def __init__(
        self,
        registry: RegistryStore,
        ledger: Ledger,
        policy: Policy,
        poster: Poster | None = None,
        *,
        token_provider: TokenProvider | None = None,
        verifier: Verifier = verify,
        nonce_factory: NonceFactory = issue_nonce,
        remote_factory: RemoteFactory = RemoteMiner,
        config: RuntimeConfig | None = None,
    ) -> None:
        self.registry = registry
        self.ledger = ledger
        self.policy = policy
        self.poster = poster
        self.token_provider = token_provider or (lambda _hotkey: None)
        self.verifier = verifier
        self.nonce_factory = nonce_factory
        self.remote_factory = remote_factory
        self.config = config or RuntimeConfig()

    def check_canary(self, canary: MinerTarget) -> MinerOutcome:
        return self._check_canary_result(canary).outcome

    def _check_canary_result(self, canary: MinerTarget) -> _CanaryResult:
        target, endpoint = self._validate_target(canary)
        result = self._collect_attestation(target, endpoint)
        if result.attested is None or result.client is None:
            raise RuntimeError(f"canary attestation failed: {result.error or 'rejected'}")

        lane = SatLane(namespace=f"canary:{target.hotkey}")
        item = lane.dispatch(target.hotkey, budget=1)
        if not isinstance(item, SatWorkItem):
            raise RuntimeError("canary did not receive canonical SAT work")
        certificate, error = self._request_sat(result.client, item)
        accepted = lane.verify(item, certificate) if certificate is not None else None
        if accepted is None:
            raise RuntimeError(f"canary SAT failed: {error or 'invalid certificate'}")
        units = lane.score(target.hotkey, [accepted])
        if units <= 0:
            raise RuntimeError("canary SAT produced no verified work")
        return _CanaryResult(
            outcome=MinerOutcome(
                hotkey=target.hotkey,
                endpoint_url=endpoint,
                status="canary_verified",
                admitted=True,
                challenge_id=item.challenge_id,
                work_units=units,
            ),
            attestation=result,
        )

    def run_epoch(
        self,
        source_epoch: int,
        canary: MinerTarget,
        *,
        publish: bool = False,
    ) -> EpochRun:
        if not isinstance(publish, bool):
            raise ValueError("publish must be a boolean")
        canary_target, canary_endpoint = self._validate_target(canary)

        enrollments = self.registry.enrollments()
        targets = [
            MinerTarget(
                enrollment.hotkey,
                enrollment.endpoint_url,
                self.token_provider(enrollment.hotkey),
            )
            for enrollment in enrollments
        ]
        self._validate_required_auth((canary_target, *targets))
        prepared, outcomes, enrolled_endpoints = self._prepare_targets(targets)
        if canary_endpoint in enrolled_endpoints:
            raise RuntimeError("canary endpoint must be dedicated and not enrolled")

        canary_result = self._check_canary_result(canary_target)
        attested = self._attest_targets(prepared, outcomes)
        canary_attested = canary_result.attestation.attested
        assert canary_attested is not None
        if any(
            result.attested is not None
            and result.attested.chip_id == canary_attested.chip_id
            for result in attested
        ):
            raise RuntimeError("an enrolled miner shares the dedicated canary TDX chip")

        epoch_id = self.ledger.begin_epoch(source_epoch)
        try:
            admitted = self._admit_unique_chips(epoch_id, attested, outcomes)
            self._run_sat(epoch_id, source_epoch, admitted, outcomes)

            all_hotkeys = {target.hotkey for target in targets}
            scores = self.ledger.complete_epoch(epoch_id, all_hotkeys)
            outcomes = {
                hotkey: MinerOutcome(
                    hotkey=outcome.hotkey,
                    endpoint_url=outcome.endpoint_url,
                    status=outcome.status,
                    admitted=outcome.admitted,
                    challenge_id=outcome.challenge_id,
                    work_units=outcome.work_units,
                    score=scores.get(hotkey, 0.0),
                    error=outcome.error,
                )
                for hotkey, outcome in outcomes.items()
            }
            if publish:
                self.publish_completed(epoch_id)
            row = self.ledger.get_epoch(epoch_id)
            assert row is not None
            return EpochRun(
                epoch_id=epoch_id,
                source_epoch=source_epoch,
                status=str(row["status"]),
                outcomes=tuple(outcomes[key] for key in sorted(outcomes)),
                scores=scores,
                published=row["status"] == "published",
            )
        except BaseException:
            row = self.ledger.get_epoch(epoch_id)
            if row is not None and row["status"] == "running":
                self.ledger.abort_epoch(epoch_id)
            raise

    def publish_completed(self, epoch_id: int) -> Mapping[str, object]:
        if self.poster is None:
            raise RuntimeError("publisher is not configured")
        blocking = self.ledger.blocking_epoch()
        if (
            blocking is None
            or blocking["status"] != "complete"
            or blocking["epoch_id"] != epoch_id
        ):
            raise RuntimeError("epoch_id must identify the exact completed blocking epoch")
        acknowledgement = self.ledger.post_and_mark_published(epoch_id, self.poster)
        return MappingProxyType(dict(acknowledgement))

    def status(self) -> Mapping[str, object]:
        blocking = self.ledger.blocking_epoch()
        return MappingProxyType(
            {"blocking_epoch": dict(blocking) if blocking is not None else None}
        )

    def abort_running(self) -> int:
        blocking = self.ledger.blocking_epoch()
        if blocking is None or blocking["status"] != "running":
            raise RuntimeError("there is no running epoch to abort")
        epoch_id = int(blocking["epoch_id"])
        self.ledger.abort_epoch(epoch_id)
        return epoch_id

    def abandon_completed(self, epoch_id: int, reason: str) -> int:
        """Recovery path for a completed report that can never be published.

        Use when a 'complete' epoch's frozen report has aged past what the
        downstream ingest service accepts for a first publish (retry-publish
        can only resend identical bytes, so that report is permanently stuck).
        Requires a nonempty operator reason; see
        ``Ledger.abandon_completed_epoch`` for the full audit and payability
        guarantees.
        """
        blocking = self.ledger.blocking_epoch()
        if (
            blocking is None
            or blocking["status"] != "complete"
            or blocking["epoch_id"] != epoch_id
        ):
            raise RuntimeError("epoch_id must identify the exact completed blocking epoch")
        self.ledger.abandon_completed_epoch(epoch_id, reason)
        return epoch_id

    def _prepare_targets(
        self, targets: list[MinerTarget]
    ) -> tuple[list[tuple[MinerTarget, str]], dict[str, MinerOutcome], frozenset[str]]:
        prepared: list[tuple[MinerTarget, str]] = []
        outcomes: dict[str, MinerOutcome] = {}
        groups: dict[str, list[MinerTarget]] = {}
        for target in targets:
            try:
                checked, endpoint = self._validate_target(target)
            except (TypeError, ValueError, RuntimeError) as exc:
                outcomes[target.hotkey] = MinerOutcome(
                    target.hotkey, target.endpoint_url, "invalid_endpoint", error=str(exc)
                )
                continue
            prepared.append((checked, endpoint))
            groups.setdefault(endpoint, []).append(checked)

        duplicate_hotkeys = {
            target.hotkey for group in groups.values() if len(group) > 1 for target in group
        }
        unique: list[tuple[MinerTarget, str]] = []
        for target, endpoint in prepared:
            if target.hotkey in duplicate_hotkeys:
                outcomes[target.hotkey] = MinerOutcome(
                    target.hotkey,
                    endpoint,
                    "duplicate_endpoint",
                    error="all claimants of a duplicate endpoint are excluded",
                )
            else:
                unique.append((target, endpoint))
        return unique, outcomes, frozenset(groups)

    def _attest_targets(
        self,
        prepared: list[tuple[MinerTarget, str]],
        outcomes: dict[str, MinerOutcome],
    ) -> list[_AttestationResult]:
        results: list[_AttestationResult] = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures: dict[str, Future[_AttestationResult]] = {
                target.hotkey: executor.submit(self._collect_attestation, target, endpoint)
                for target, endpoint in prepared
            }
            by_hotkey = {target.hotkey: (target, endpoint) for target, endpoint in prepared}
            for hotkey in sorted(futures):
                result = futures[hotkey].result()
                if result.attested is None:
                    target, endpoint = by_hotkey[hotkey]
                    outcomes[hotkey] = MinerOutcome(
                        hotkey, endpoint, "attestation_failed", error=result.error
                    )
                else:
                    results.append(result)
        return results

    def _admit_unique_chips(
        self,
        epoch_id: int,
        results: list[_AttestationResult],
        outcomes: dict[str, MinerOutcome],
    ) -> list[_AttestationResult]:
        chip_groups: dict[str, list[_AttestationResult]] = {}
        for result in results:
            assert result.attested is not None
            chip_groups.setdefault(result.attested.chip_id, []).append(result)

        admitted: list[_AttestationResult] = []
        for chip_id in sorted(chip_groups):
            group = chip_groups[chip_id]
            if len(group) > 1:
                for result in group:
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "duplicate_chip",
                        error="all claimants of a duplicate chip are excluded",
                    )
                continue
            result = group[0]
            assert result.attested is not None and result.evidence_digest is not None
            self.ledger.add_attestation(
                epoch_id,
                result.target.hotkey,
                verdict="VERIFIED",
                tee_type="TDX",
                workload="CPU",
                evidence_digest=result.evidence_digest,
            )
            outcomes[result.target.hotkey] = MinerOutcome(
                result.target.hotkey, result.endpoint, "attested", admitted=True
            )
            admitted.append(result)
        return sorted(admitted, key=lambda result: result.target.hotkey)

    def _run_sat(
        self,
        epoch_id: int,
        source_epoch: int,
        admitted: list[_AttestationResult],
        outcomes: dict[str, MinerOutcome],
    ) -> None:
        lane = SatLane(namespace=f"source-epoch:{source_epoch}:attempt:{epoch_id}")
        issued: list[tuple[_AttestationResult, SatWorkItem]] = []
        for result in admitted:
            item = lane.dispatch(result.target.hotkey, budget=1)
            if not isinstance(item, SatWorkItem):
                raise RuntimeError("SAT lane returned a non-canonical work item")
            self.ledger.issue_challenge(item.challenge_id, result.target.hotkey, epoch_id)
            issued.append((result, item))

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(self._request_sat, result.client, item)
                for result, item in issued
            ]
            for (result, item), future in zip(issued, futures, strict=True):
                certificate, error = future.result()
                accepted = lane.verify(item, certificate) if certificate is not None else None
                if accepted is None:
                    self.ledger.resolve_challenge(item.challenge_id, "failed")
                    outcomes[result.target.hotkey] = MinerOutcome(
                        result.target.hotkey,
                        result.endpoint,
                        "sat_failed",
                        admitted=True,
                        challenge_id=item.challenge_id,
                        error=error or "invalid SAT certificate",
                    )
                    continue
                units = lane.score(result.target.hotkey, [accepted])
                self.ledger.resolve_challenge(
                    item.challenge_id,
                    "verified",
                    units,
                    validator_derived=True,
                )
                outcomes[result.target.hotkey] = MinerOutcome(
                    result.target.hotkey,
                    result.endpoint,
                    "verified",
                    admitted=True,
                    challenge_id=item.challenge_id,
                    work_units=units,
                )

    def _collect_attestation(self, target: MinerTarget, endpoint: str) -> _AttestationResult:
        try:
            client = self.remote_factory(
                endpoint,
                target.hotkey,
                bearer_token=target.bearer_token,
                timeout=self.config.miner_timeout_seconds,
                allow_insecure_http=self.config.allow_insecure_http_for_tests,
            )
        except Exception as exc:
            return _AttestationResult(target, endpoint, error=_safe_error(exc))

        last_error = "attestation rejected"
        for _ in range(self.config.miner_attempts):
            try:
                nonce = self.nonce_factory()
                if not isinstance(nonce, bytes) or len(nonce) != 32:
                    raise RuntimeError("nonce_factory must return exactly 32 bytes")
                evidence = client.collect_evidence(nonce)
                if evidence.nonce != nonce:
                    raise RuntimeError("evidence nonce mismatch")
                if evidence.miner_hotkey != target.hotkey:
                    raise RuntimeError("evidence hotkey mismatch")
                if evidence.kind is not EvidenceKind.TDX:
                    raise RuntimeError("evidence kind must be TDX")
                verdict = self.verifier(evidence, nonce, self.policy)
                if verdict is None:
                    raise RuntimeError("TDX verification rejected")
                if verdict.verification_status != "VERIFIED" or verdict.tier is not Tier.CC_CPU_TDX:
                    raise RuntimeError("verdict must be exact VERIFIED CC_CPU_TDX")
                if not verdict.chip_id:
                    raise RuntimeError("verified TDX evidence must identify a chip")
                return _AttestationResult(
                    target,
                    endpoint,
                    attested=verdict,
                    evidence_digest=_evidence_digest(evidence),
                    client=client,
                )
            except Exception as exc:
                last_error = _safe_error(exc)
        return _AttestationResult(target, endpoint, error=last_error)

    def _request_sat(
        self, client: MinerClient | None, item: SatWorkItem
    ) -> tuple[SatCertificate | None, str | None]:
        if client is None:
            return None, "miner client unavailable"
        last_error = "SAT request failed"
        for _ in range(self.config.miner_attempts):
            try:
                return client.do_sat_work(item), None
            except Exception as exc:
                last_error = _safe_error(exc)
        return None, last_error

    def _validate_target(self, target: MinerTarget) -> tuple[MinerTarget, str]:
        if not isinstance(target, MinerTarget):
            raise TypeError("target must be a MinerTarget")
        if not isinstance(target.hotkey, str) or not target.hotkey:
            raise ValueError("target hotkey must be a nonempty string")
        _validate_bearer_token(
            target.bearer_token,
            required=self.config.production_mode,
        )
        endpoint = _canonical_endpoint(target.endpoint_url, self.config)
        return target, endpoint

    def _validate_required_auth(self, targets: tuple[MinerTarget, ...]) -> None:
        if not self.config.production_mode:
            return
        for target in targets:
            try:
                _validate_bearer_token(target.bearer_token, required=True)
            except ValueError as exc:
                raise RuntimeError(
                    f"production bearer authentication is required for target {target.hotkey!r}"
                ) from exc


def _canonical_endpoint(endpoint: str, config: RuntimeConfig) -> str:
    if not isinstance(endpoint, str):
        raise ValueError("endpoint must be a string")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("endpoint must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint must not contain query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("endpoint must not contain a path")
    if parsed.scheme != "https" and not config.allow_insecure_http_for_tests:
        raise ValueError("endpoint must use HTTPS")

    host = parsed.hostname.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if config.production_mode:
            raise ValueError("production endpoint must use a public IP literal") from None
    else:
        if config.production_mode and not ip.is_global:
            raise ValueError("production endpoint must use a public address")
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint port is invalid") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    authority = host if port in {None, default_port} else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}"


def _validate_bearer_token(token: str | None, *, required: bool) -> None:
    if token is None and not required:
        return
    if (
        not isinstance(token, str)
        or not token
        or len(token) > MAX_BEARER_TOKEN_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
    ):
        raise ValueError("bearer token must be a nonempty bounded ASCII value")


def _evidence_digest(evidence: Evidence) -> str:
    digest = hashlib.sha256()
    for value in (
        evidence.kind.value.encode("ascii"),
        evidence.quote,
        evidence.nonce,
        evidence.miner_hotkey.encode("utf-8"),
        *evidence.cert_chain,
    ):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _safe_error(exc: BaseException) -> str:
    message = str(exc).strip()
    return message[:300] if message else type(exc).__name__
