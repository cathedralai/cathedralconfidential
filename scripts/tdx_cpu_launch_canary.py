#!/usr/bin/env python3
"""Run the production CPU launch contract against two disposable TDX workers.

The dedicated canary and enrolled worker must be different TDX platforms with
public-IP HTTPS endpoints.  Each endpoint must terminate its TLS private key
inside the guest and bind that key's SPKI digest into configfs TDX evidence.

This runner creates fresh ephemeral policy and receipt signing keys, exercises
the production signed-registry and static-verifier path, routes one bounded
customer SAT job, reopens the SQLite ledger, and verifies the exact persisted
receipt.  Only public verification artifacts are retained in ``--evidence-dir``;
private keys and bearer credentials are never written there.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.cli import (
    _load_receipt_private_seed,
    _verified_registry_snapshot_and_policy,
)
from cathedral.channel import ChannelBindingError, tls_spki_binding
from cathedral.common import ChannelBinding, Evidence, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.ledger import Ledger
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.policy_registry import (
    PolicyRegistrySnapshot,
    canonical_json,
    sign_registry,
)
from cathedral.receipt import ReceiptIssuer, verify_receipt
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.runtime import (
    ConfidentialRuntime,
    MinerTarget,
    RuntimeConfig,
    _canonical_endpoint,
)


_MEASUREMENT_RE = re.compile(r"^tdx-measurement-sha256:[0-9a-f]{64}$")
_MAX_CERTIFICATE_BYTES = 256 * 1024
_POLICY_KEY_ID = "tdx-cpu-canary-policy-1"
_RECEIPT_KEY_ID = "tdx-cpu-canary-receipt-1"
_REGISTRY_RELEASE = 1
_RUNTIME_MEASUREMENT = (
    "runtime-sha256:" + hashlib.sha256(b"cathedral-tdx-cpu-launch-canary-v1").hexdigest()
)


class LaunchCanaryError(RuntimeError):
    """The launch canary could not prove one of its required invariants."""


@dataclass(frozen=True)
class _EndpointTlsPin:
    context: ssl.SSLContext
    binding: ChannelBinding


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LaunchCanaryError(message)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _canonical_second(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_registry(
    measurements: Sequence[str],
    policy_seed: bytes,
    receipt_seed: bytes,
    *,
    now: datetime | None = None,
) -> bytes:
    """Return one fresh strict CPU registry for an isolated launch canary."""

    if not measurements or any(
        not isinstance(item, str) or _MEASUREMENT_RE.fullmatch(item) is None
        for item in measurements
    ):
        raise LaunchCanaryError("every measurement must be a canonical TDX SHA-256 digest")
    if len(set(measurements)) != len(measurements):
        raise LaunchCanaryError("measurements must be unique")
    if not isinstance(policy_seed, bytes) or len(policy_seed) != 32:
        raise LaunchCanaryError("policy seed must be exactly 32 bytes")
    if not isinstance(receipt_seed, bytes) or len(receipt_seed) != 32:
        raise LaunchCanaryError("receipt seed must be exactly 32 bytes")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    generated_at = _canonical_second(current - timedelta(minutes=2))
    valid_from = _canonical_second(current - timedelta(minutes=1))
    valid_until = _canonical_second(current + timedelta(hours=1))
    unsigned = {
        "schema": "cathedral_policy_registry_v1",
        "release": _REGISTRY_RELEASE,
        "generated_at": generated_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "signing_key_id": _POLICY_KEY_ID,
        "receipt_signing_keys": [
            {
                "id": _RECEIPT_KEY_ID,
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(_public_key(receipt_seed)).decode("ascii"),
                "purpose": "assurance_receipt",
                "status": "active",
                "status_changed_at": valid_from,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "revoked_at": None,
                "replacement_key_id": None,
                "metadata": {"environment": "disposable-launch-canary"},
            }
        ],
        "profiles": [
            {
                "id": "cpu-tdx-launch-canary-v1",
                "kind": "cpu_tdx",
                "status": "active",
                "status_changed_at": valid_from,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "retire_at": None,
                "measurements": sorted(measurements),
                "runtime_measurements": [_RUNTIME_MEASUREMENT],
                "allowed_firmware": [],
                "min_tcb": 0,
                "tdx_allowed_tcb_statuses": ["UpToDate"],
                "tdx_allowed_advisories": [],
                "metadata": {
                    "description": "Disposable strict CPU launch canary",
                },
            }
        ],
        "metadata": {
            "critical": True,
            "purpose": "isolated full-path CPU launch evidence",
        },
    }
    return canonical_json(sign_registry(unsigned, policy_seed))


def _read_certificate(path: Path) -> tuple[str, ChannelBinding]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise LaunchCanaryError("unable to read an endpoint certificate") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise LaunchCanaryError("endpoint certificates must be regular non-symlink files")
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise LaunchCanaryError("unable to read an endpoint certificate") from exc
    if not encoded or len(encoded) > _MAX_CERTIFICATE_BYTES:
        raise LaunchCanaryError("endpoint certificate size is invalid")
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LaunchCanaryError("endpoint certificates must be ASCII PEM") from exc
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise LaunchCanaryError(
            "each endpoint certificate file must contain exactly one certificate"
        )
    start = text.find(begin)
    finish = text.find(end) + len(end)
    if text[:start].strip() or text[finish:].strip():
        raise LaunchCanaryError("endpoint certificate files must contain only one PEM certificate")
    try:
        certificate = x509.load_pem_x509_certificate(encoded)
        binding = tls_spki_binding(certificate.public_bytes(serialization.Encoding.DER))
    except (ValueError, ChannelBindingError) as exc:
        raise LaunchCanaryError("endpoint certificate is invalid") from exc
    return text, binding


def build_tls_pin(certificate: Path) -> _EndpointTlsPin:
    pem, binding = _read_certificate(certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=pem)
    return _EndpointTlsPin(context, binding)


def _write_private_seed(path: Path, seed: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, base64.b64encode(seed) + b"\n")
    finally:
        os.close(descriptor)


def _prepare_evidence_dir(path: Path) -> None:
    if path.exists():
        raise LaunchCanaryError("evidence directory must not already exist")
    path.mkdir(mode=0o700, parents=True)
    if path.is_symlink() or not path.is_dir():
        raise LaunchCanaryError("evidence directory is invalid")


class _PinnedRemoteMiner(RemoteMiner):
    """Require the live TLS key to match the designated endpoint certificate."""

    def __init__(
        self,
        endpoint: str,
        hotkey: str,
        *,
        expected_binding: ChannelBinding,
        **kwargs: object,
    ) -> None:
        self._expected_endpoint_binding = expected_binding
        super().__init__(endpoint, hotkey, **kwargs)  # type: ignore[arg-type]

    def fetch_evidence_bundle(self, nonce: bytes) -> tuple[Evidence, ...]:
        evidences = super().fetch_evidence_bundle(nonce)
        if any(
            evidence.channel_binding != self._expected_endpoint_binding for evidence in evidences
        ):
            self._pending_binding = None
            self._trusted_binding = None
            raise RemoteError("worker TLS key does not match its pinned endpoint certificate")
        return evidences


def _remote_factory(pins: dict[str, _EndpointTlsPin]) -> Callable[..., RemoteMiner]:
    def build(endpoint: str, hotkey: str, **kwargs: object) -> RemoteMiner:
        try:
            pin = pins[endpoint]
        except KeyError:
            raise LaunchCanaryError("runtime requested an unpinned endpoint") from None
        return _PinnedRemoteMiner(
            endpoint,
            hotkey,
            expected_binding=pin.binding,
            ssl_context=pin.context,
            **kwargs,
        )

    return build


def build_tls_pins(
    canary_endpoint: str,
    canary_certificate: Path,
    worker_endpoint: str,
    worker_certificate: Path,
    config: RuntimeConfig,
) -> dict[str, _EndpointTlsPin]:
    canonical_canary = _canonical_endpoint(canary_endpoint, config)
    canonical_worker = _canonical_endpoint(worker_endpoint, config)
    _require(
        canonical_canary != canonical_worker,
        "canary and worker endpoints must differ",
    )
    canary_pin = build_tls_pin(canary_certificate)
    worker_pin = build_tls_pin(worker_certificate)
    _require(
        canary_pin.binding != worker_pin.binding,
        "canary and worker endpoint TLS keys must differ",
    )
    return {canonical_canary: canary_pin, canonical_worker: worker_pin}


def _load_token(environment_name: str) -> str:
    token = os.environ.get(environment_name)
    if token is None:
        raise LaunchCanaryError(f"bearer token must be set in {environment_name}")
    return token


def _policy_authority(
    registry_path: Path,
    keys_path: Path,
    state_path: Path,
    keys_digest: str,
) -> tuple[Policy, PolicyRegistrySnapshot]:
    return _verified_registry_snapshot_and_policy(
        str(registry_path),
        str(keys_path),
        state_path=str(state_path),
        minimum_release=_REGISTRY_RELEASE,
        max_age_seconds=3600,
        production_mode=True,
        trusted_keys_digest=keys_digest,
    )


def run(args: argparse.Namespace) -> dict[str, object]:
    evidence_dir = Path(args.evidence_dir).resolve()
    _prepare_evidence_dir(evidence_dir)

    runtime_config = RuntimeConfig(
        miner_timeout_seconds=args.miner_timeout_seconds,
        miner_attempts=2,
        max_workers=2,
        production_mode=True,
        customer_job_lease_seconds=180,
        customer_job_max_attempts=3,
        expected_tier=Tier.CC_CPU_TDX,
        admission_enabled=True,
        score_network=args.score_network,
        score_netuid=args.score_netuid,
    )
    measurements = tuple(args.measurement)
    canary_token = _load_token(args.canary_bearer_env)
    worker_token = _load_token(args.worker_bearer_env)
    tls_pins = build_tls_pins(
        args.canary_endpoint,
        Path(args.canary_certificate),
        args.worker_endpoint,
        Path(args.worker_certificate),
        runtime_config,
    )

    policy_seed = secrets.token_bytes(32)
    receipt_seed = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-launch-") as private_root:
        private_dir = Path(private_root)
        registry_path = private_dir / "policy-registry.json"
        keys_path = private_dir / "trusted-policy-keys.json"
        state_path = private_dir / "policy-state.sqlite"
        receipt_key_path = private_dir / "receipt-key.seed"
        registry_db = private_dir / "registry.sqlite"
        ledger_db = private_dir / "ledger.sqlite"

        registry_bytes = build_registry(measurements, policy_seed, receipt_seed)
        trusted_keys_bytes = canonical_json(
            {_POLICY_KEY_ID: base64.b64encode(_public_key(policy_seed)).decode("ascii")}
        )
        registry_path.write_bytes(registry_bytes)
        keys_path.write_bytes(trusted_keys_bytes)
        _write_private_seed(receipt_key_path, receipt_seed)
        keys_digest = "sha256:" + hashlib.sha256(trusted_keys_bytes).hexdigest()

        policy, snapshot = _policy_authority(registry_path, keys_path, state_path, keys_digest)

        def refresh_policy() -> Policy:
            refreshed, _snapshot = _policy_authority(
                registry_path, keys_path, state_path, keys_digest
            )
            return refreshed

        registry = RegistryStore(str(registry_db))
        registry.enroll(args.worker_hotkey, args.worker_endpoint)
        ledger = Ledger(ledger_db)
        customer_instance = SatInstance(
            n_vars=3,
            clauses=[[1, -2, 3], [-1, 2], [3]],
        )
        customer_seed = 7
        submitted = ledger.enqueue_customer_job(
            SatWorkItem(
                customer_instance,
                customer_seed,
                _compute_challenge_id(customer_instance, customer_seed),
            ),
            customer_id="public-launch-canary",
            idempotency_key="full-cpu-launch-canary-v1",
        )
        receipt_issuer = ReceiptIssuer(
            snapshot,
            _RECEIPT_KEY_ID,
            _load_receipt_private_seed(str(receipt_key_path), production_mode=True),
        )
        runtime = ConfidentialRuntime(
            registry,
            ledger,
            policy,
            token_provider=lambda hotkey: worker_token if hotkey == args.worker_hotkey else None,
            policy_refresher=refresh_policy,
            remote_factory=_remote_factory(tls_pins),
            config=runtime_config,
            receipt_issuer=receipt_issuer,
        )
        try:
            epoch = runtime.run_epoch(
                args.source_epoch,
                MinerTarget(args.canary_hotkey, args.canary_endpoint, canary_token),
            )
            worker_outcomes = [item for item in epoch.outcomes if item.hotkey == args.worker_hotkey]
            _require(len(worker_outcomes) == 1, "epoch did not contain exactly one worker outcome")
            outcome = worker_outcomes[0]
            _require(outcome.status == "verified", "enrolled worker did not verify customer work")
            _require(outcome.challenge_id is not None, "verified worker has no challenge ID")
            epoch_id = epoch.epoch_id
            challenge_id = outcome.challenge_id
            report_bytes = ledger.report_bytes(epoch_id)
        finally:
            runtime.close()
            ledger.close()

        with Ledger(ledger_db) as reopened:
            customer = reopened.customer_job(submitted.job_id)
            stored = reopened.receipt_for_challenge(challenge_id)
            _require(customer.status == "succeeded", "customer job was not durably successful")
            _require(customer.attempt_count == 1, "customer job did not succeed in one attempt")
            _require(customer.result is not None, "customer result was not persisted")
            _require(stored is not None, "assurance receipt was not persisted")
            receipt_bytes = stored["receipt_body"]
            _require(isinstance(receipt_bytes, bytes), "stored receipt bytes are invalid")
            receipt = verify_receipt(receipt_bytes, snapshot)
            _require(
                stored["receipt_id"] == receipt.receipt_id,
                "reopened receipt ID does not match its exact bytes",
            )
            _require(
                stored["receipt_digest"] == receipt.receipt_digest,
                "reopened receipt digest does not match its exact bytes",
            )

        report = json.loads(report_bytes)
        result = {
            "schema": "cathedral_tdx_cpu_launch_canary_v1",
            "canary_attestation": "verified",
            "customer_job_id": submitted.job_id,
            "customer_job_status": customer.status,
            "customer_attempt_count": customer.attempt_count,
            "customer_result_persisted": customer.result is not None,
            "epoch_id": epoch_id,
            "epoch_status": epoch.status,
            "source_epoch": epoch.source_epoch,
            "worker_hotkey": args.worker_hotkey,
            "worker_outcome": outcome.status,
            "worker_score": epoch.scores.get(args.worker_hotkey),
            "challenge_id": challenge_id,
            "receipt_id": receipt.receipt_id,
            "receipt_digest": receipt.receipt_digest,
            "receipt_offline_verification": "verified",
            "receipt_tcb_status": receipt.document["tcb"]["status"],
            "receipt_tcb_advisories": receipt.document["tcb"]["advisory_ids"],
            "receipt_collateral_current": receipt.document["tcb"]["collateral_current"],
            "receipt_debug_enabled": receipt.document["tcb"]["debug_enabled"],
            "registry_release": snapshot.release,
            "registry_digest": snapshot.digest,
            "trusted_keys_digest": keys_digest,
            "measurements": list(measurements),
            "report_digest": "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
            "report_complete": report.get("complete"),
            "static_verifier_digest": os.environ.get("CATHEDRAL_TDX_VERIFY_DIGEST"),
        }
        result_bytes = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

        (evidence_dir / "policy-registry.json").write_bytes(registry_bytes)
        (evidence_dir / "trusted-policy-keys.json").write_bytes(trusted_keys_bytes)
        (evidence_dir / "assurance-receipt.json").write_bytes(receipt_bytes)
        (evidence_dir / "epoch-report.json").write_bytes(report_bytes)
        (evidence_dir / "result.json").write_bytes(result_bytes)

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove the signed, TLS-bound, durable Cathedral CPU launch path"
    )
    parser.add_argument("--canary-hotkey", required=True)
    parser.add_argument("--canary-endpoint", required=True)
    parser.add_argument("--canary-certificate", required=True)
    parser.add_argument("--canary-bearer-env", default="CATHEDRAL_CANARY_BEARER_TOKEN")
    parser.add_argument("--worker-hotkey", required=True)
    parser.add_argument("--worker-endpoint", required=True)
    parser.add_argument("--worker-certificate", required=True)
    parser.add_argument("--worker-bearer-env", default="CATHEDRAL_WORKER_BEARER_TOKEN")
    parser.add_argument("--measurement", action="append", required=True)
    parser.add_argument("--source-epoch", type=int, default=1)
    parser.add_argument("--score-network", required=True)
    parser.add_argument("--score-netuid", type=int, required=True)
    parser.add_argument("--miner-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--evidence-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run(args)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
