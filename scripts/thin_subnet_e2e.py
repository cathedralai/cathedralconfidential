#!/usr/bin/env python3
"""Local Cathedral Confidential -> thin validator end-to-end proof."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.assurance import (
    AssuranceDimension,
    ClaimStatus,
    attestation_claims,
    evaluated_claim,
    with_verified_channel,
)
from cathedral.common import Attested, Tier
from cathedral.ledger import Ledger
from cathedral.lifecycle import LifecycleReason, LifecycleSnapshot, WorkerLifecycleState
from cathedral.policy_registry import canonical_json, sign_registry, verify_registry
from cathedral.receipt import ReceiptIssuer
from cathedral.runtime import SAT_WORK_POLICY_DIGEST
from cathedral.score_class import export_score_class_report


NETWORK = "local"
NETUID = 1
SOURCE_EPOCH = 7
CURRENT_BLOCK = 70
HOTKEY_UNITS = {"honest-a": 1.0, "honest-a2": 1.0, "honest-b": 2.0}
REGISTRY_SEED = hashlib.sha256(b"cathedral-thin-e2e-registry").digest()
RECEIPT_SEED = hashlib.sha256(b"cathedral-thin-e2e-receipts").digest()
SCORE_SEED = hashlib.sha256(b"cathedral-thin-e2e-score-class").digest()


class IntegrationProofError(RuntimeError):
    """The local integration proof did not establish a required invariant."""


def _time(value: datetime, *, micros: bool = False) -> str:
    pattern = "%Y-%m-%dT%H:%M:%S.%fZ" if micros else "%Y-%m-%dT%H:%M:%SZ"
    return value.astimezone(UTC).strftime(pattern)


def _public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def _registry(now: datetime):
    valid_from = now - timedelta(minutes=1)
    valid_until = now + timedelta(hours=1)
    registry_document = {
        "schema": "cathedral_policy_registry_v1",
        "release": 1,
        "generated_at": _time(now - timedelta(minutes=2)),
        "valid_from": _time(valid_from),
        "valid_until": _time(valid_until),
        "signing_key_id": "cathedral-thin-e2e-registry",
        "receipt_signing_keys": [
            {
                "id": "cathedral-thin-e2e-receipts",
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(_public(RECEIPT_SEED)).decode("ascii"),
                "purpose": "assurance_receipt",
                "status": "active",
                "status_changed_at": _time(valid_from),
                "valid_from": _time(valid_from),
                "valid_until": _time(valid_until),
                "revoked_at": None,
                "replacement_key_id": None,
                "metadata": {"environment": "local-e2e"},
            }
        ],
        "profiles": [
            {
                "id": "cpu-tdx-local-e2e-v1",
                "kind": "cpu_tdx",
                "status": "active",
                "status_changed_at": _time(valid_from),
                "valid_from": _time(valid_from),
                "valid_until": _time(valid_until),
                "retire_at": None,
                "measurements": ["tdx-measurement-sha256:local-e2e"],
                "runtime_measurements": ["runtime-sha256:local-e2e"],
                "allowed_firmware": [],
                "min_tcb": 0,
                "tdx_allowed_tcb_statuses": ["UpToDate"],
                "tdx_allowed_advisories": [],
                "metadata": {"purpose": "local cross-repository proof"},
            }
        ],
        "metadata": {"purpose": "local cross-repository proof"},
    }
    signed = canonical_json(sign_registry(registry_document, REGISTRY_SEED))
    return verify_registry(
        signed,
        {"cathedral-thin-e2e-registry": _public(REGISTRY_SEED)},
        now=now,
        max_age_seconds=3600,
    )


def _lifecycle(policy: Any, claims: Any, hotkey: str, now: datetime) -> LifecycleSnapshot:
    return LifecycleSnapshot(
        hotkey=hotkey,
        state=WorkerLifecycleState.ATTESTED,
        generation=1,
        revision=2,
        event_id=2,
        reason=LifecycleReason.ATTESTATION_VERIFIED,
        state_changed_at=now,
        evidence_verified_at=now,
        evidence_expires_at=now + timedelta(minutes=30),
        measurement="tdx-measurement-sha256:local-e2e",
        evidence_digest=claims.hardware.evidence_digest,
        policy_digest=claims.software.policy_digest,
        policy_registry_release=policy.registry_release,
        policy_registry_digest=policy.registry_digest,
    )


def _verifier_digest(repo: Path) -> str:
    digest = hashlib.sha256(b"cathedral-score-class-verifier-v1\x00")
    for relative in ("cathedral/receipt.py", "cathedral/score_class.py"):
        digest.update(relative.encode("ascii") + b"\x00")
        digest.update((repo / relative).read_bytes())
    return "sha256:" + digest.hexdigest()


def _git_head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _build_report(repo: Path, directory: Path) -> tuple[bytes, bytes, list[str], str]:
    now = datetime.now(UTC).replace(microsecond=123456)
    snapshot = _registry(now)
    policy = snapshot.to_policy(at=now)
    issuer = ReceiptIssuer(
        snapshot,
        "cathedral-thin-e2e-receipts",
        RECEIPT_SEED,
        clock=lambda: now,
    )
    ledger = Ledger(directory / "cathedralconfidential.sqlite")
    epoch_id = ledger.begin_epoch(
        SOURCE_EPOCH,
        policy_registry_release=snapshot.release,
        policy_registry_digest=snapshot.digest,
    )
    receipt_ids: list[str] = []
    for hotkey, units in HOTKEY_UNITS.items():
        verified_at = _time(now, micros=True)
        claims = attestation_claims(("quote:" + hotkey).encode(), policy, verified_at=verified_at)
        claims = with_verified_channel(
            claims,
            ("channel:" + hotkey).encode(),
            verified_at=verified_at,
        )
        claims = claims.with_claim(
            AssuranceDimension.WORK,
            evaluated_claim(
                ClaimStatus.PASSED,
                ("result:" + hotkey).encode(),
                SAT_WORK_POLICY_DIGEST,
                verified_at=verified_at,
            ),
        )
        attested = Attested(
            tier=Tier.CC_CPU_TDX,
            chip_id="tdx-platform-sha256:" + hashlib.sha256(hotkey.encode()).hexdigest(),
            measurement="tdx-measurement-sha256:local-e2e",
            tcb=1,
            tcb_status="UpToDate",
            advisory_ids=(),
            debug_enabled=False,
            collateral_current=True,
            tcb_svn="01" * 16,
            policy_mode="strict",
            assurance=claims,
        )
        challenge_id = hashlib.sha256(("challenge:" + hotkey).encode()).hexdigest()
        receipt = issuer.issue(
            epoch_id=epoch_id,
            source_epoch=SOURCE_EPOCH,
            subject_hotkey=hotkey,
            attested=attested,
            policy=policy,
            assurance=claims,
            worker_lifecycle=_lifecycle(policy, claims, hotkey, now),
            challenge_id=challenge_id,
            manifest_digest="sha256:" + hashlib.sha256(("manifest:" + hotkey).encode()).hexdigest(),
            work_units=units,
            issued_at=now,
        )
        ledger.issue_challenge(challenge_id, hotkey, epoch_id)
        ledger.resolve_challenge_with_receipt(
            challenge_id,
            "verified",
            units,
            validator_derived=True,
            receipt_id=receipt.receipt_id,
            receipt_body=receipt.receipt_bytes,
            receipt_digest=receipt.receipt_digest,
            issued_at=verified_at,
        )
        ledger.add_attestation(
            epoch_id,
            hotkey,
            verdict="VERIFIED",
            tee_type="TDX",
            workload="CPU",
            evidence_digest=claims.hardware.evidence_digest,
            policy_mode="strict",
        )
        ledger.add_lifecycle_snapshot(
            epoch_id,
            _lifecycle(policy, claims, hotkey, now),
            snapshot_at=verified_at,
        )
        receipt_ids.append(receipt.receipt_id)
    ledger.complete_epoch(
        epoch_id,
        set(HOTKEY_UNITS),
        generated_at=_time(now, micros=True),
        score_network=NETWORK,
        score_netuid=NETUID,
    )
    verifier_digest = _verifier_digest(repo)
    report = export_score_class_report(
        ledger,
        epoch_id,
        network=NETWORK,
        netuid=NETUID,
        class_id="confidential_compute",
        source_id="cathedralconfidential",
        signing_key_id="e2e-score-key",
        private_key_seed=SCORE_SEED,
        generated_at=now,
        valid_until=now + timedelta(minutes=5),
        valid_from_block=CURRENT_BLOCK,
        valid_until_block=CURRENT_BLOCK + 10,
        verifier_digest=verifier_digest,
        evidence_base_uri="https://evidence.local/receipts/",
    )
    return report, _public(SCORE_SEED), sorted(receipt_ids), verifier_digest


def run_proof(validator_repo: Path) -> dict[str, Any]:
    source_repo = Path(__file__).resolve().parents[1]
    validator_repo = validator_repo.expanduser().resolve()
    if not (validator_repo / "cathedral_thin" / "e2e.py").is_file():
        raise IntegrationProofError("validator repository lacks cathedral_thin/e2e.py")
    sys.path.insert(0, str(validator_repo))
    from cathedral_thin.core import ThinSubnetError
    from cathedral_thin.e2e import run_e2e
    from cathedral_thin.score_classes import (
        AssignmentPolicy,
        ExternalClassPolicy,
        canonical_json as validator_canonical_json,
        verify_report,
    )

    with tempfile.TemporaryDirectory(prefix="cathedral-thin-cross-repo-") as tmp:
        report, public_key, receipt_ids, verifier_digest = _build_report(source_repo, Path(tmp))
        now = datetime.now(UTC)
        policy = ExternalClassPolicy(
            class_id="confidential_compute",
            allocation=Decimal("1"),
            source_id="cathedralconfidential",
            locations=(),
            trusted_keys={"e2e-score-key": public_key},
            max_age_seconds=600,
            max_future_seconds=30,
            max_block_span=100,
            require_evidence=True,
            assignment=AssignmentPolicy(
                mode="metric",
                metric="verified_work_units",
                transform="linear",
                cap=Decimal("10"),
                required_reason_codes=("receipt_verified", "work_verified"),
                required_evidence_kinds=("cathedral_assurance_receipt_v2",),
            ),
        )
        verified = verify_report(
            report,
            policy,
            network=NETWORK,
            netuid=NETUID,
            current_block=CURRENT_BLOCK,
            now=now,
        )
        evidence_uris = sorted(
            evidence.uri
            for entry in verified.entries
            for evidence in entry.evidence
            if evidence.uri is not None
        )
        document = json.loads(report)
        document["entries"][0]["metrics"]["verified_work_units"] = "9"
        tampered = validator_canonical_json(document)
        tamper_rejected = False
        try:
            verify_report(
                tampered,
                policy,
                network=NETWORK,
                netuid=NETUID,
                current_block=CURRENT_BLOCK,
                now=now,
            )
        except ThinSubnetError:
            tamper_rejected = True

        validator = asyncio.run(
            run_e2e(
                external_report_raw=report,
                external_public_key=public_key,
            )
        )
        observed_receipts = validator["score_classes"]["receipt_evidence_ids"]
        ok = all(
            (
                validator["ok"],
                validator["score_classes"]["report_origin"] == "external_report_bytes",
                validator["score_classes"]["external_hotkeys"] == sorted(HOTKEY_UNITS),
                observed_receipts == receipt_ids,
                len(evidence_uris) == len(receipt_ids),
                all(uri.startswith("https://evidence.local/receipts/") for uri in evidence_uris),
                tamper_rejected,
                abs(sum(item["weight"] for item in validator["onchain_vector"]) - 1.0) < 1e-9,
            )
        )
        return {
            "schema": "cathedral.thin.cross_repo.e2e.v1",
            "ok": ok,
            "source_repo_head": _git_head(source_repo),
            "validator_repo_head": _git_head(validator_repo),
            "report_id": verified.report_id,
            "source_epoch": verified.source_epoch,
            "producer": "cathedralconfidential_ledger",
            "verifier_digest": verifier_digest,
            "receipt_ids": receipt_ids,
            "evidence_uris": evidence_uris,
            "tampered_report_rejected": tamper_rejected,
            "validator": validator,
        }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Cathedral Confidential through the thin local validator"
    )
    parser.add_argument(
        "--validator-repo",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "cathedralsubnet-production-ready",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    evidence = run_proof(args.validator_repo)
    print(json.dumps(evidence, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
