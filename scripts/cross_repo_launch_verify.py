#!/usr/bin/env python3
"""Fail-closed local launch proof for confidential scoring and Cathedral weights."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import itertools
import json
import math
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from cathedral.ledger import Ledger
from cathedral.poster import Poster


SOURCE = "cathedral_confidential_tdx"
CAP = 0.10
SIGNED_FRACTION_TOLERANCE = 1e-12
NETWORK = "finney"
NETUID = 39
KEY_ID = "cathedral-weight-policy"
SIGNING_KEY_HEX = "42" * 32
BEARER_TOKEN = "cross-repo-launch-token"
HMAC_SECRET = "cross-repo-launch-hmac-secret"

BASE_WORK = {
    "miner-alpha": 100.0,
    "miner-bravo": 55.0,
    "miner-charlie": 20.0,
}
CONFIDENTIAL_ONLY = "miner-confidential-only"
ALL_HOTKEYS = tuple((*BASE_WORK, CONFIDENTIAL_ONLY))


class LaunchProofError(RuntimeError):
    """Raised whenever the launch proof cannot establish an invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LaunchProofError(message)


def _iso_millis(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _git_head(repo: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@contextlib.contextmanager
def temporary_environment(values: Mapping[str, str | None]) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def scorer_environment() -> dict[str, str | None]:
    """Return the explicit local policy used by this launch proof."""
    suffix = SOURCE.upper()
    return {
        "DATABASE_URL": None,
        "CATHEDRAL_SERVICE_ROLE": "all",
        "CATHEDRAL_V2_DATABASE_URL": None,
        "CATHEDRAL_V2_DB_PATH": None,
        "CATHEDRAL_HIPPIUS_TOKEN": None,
        "CATHEDRAL_HIPPIUS_BUCKET": None,
        "CATHEDRAL_RATELIMIT_RPM": "0",
        "CATHEDRAL_ABUSE_LIMIT_ENABLED": "0",
        "CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED": "1",
        "CATHEDRAL_EXTERNAL_SCORES_TOKEN": None,
        f"CATHEDRAL_EXTERNAL_SCORES_TOKEN_{suffix}": BEARER_TOKEN,
        "CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET": None,
        f"CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET_{suffix}": HMAC_SECRET,
        "CATHEDRAL_EXTERNAL_SCORES_ALLOW_UNAUTHENTICATED": "0",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS": "3600",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS": "120",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES": "1048576",
        "CATHEDRAL_EXTERNAL_SCORES_ENABLED": "1",
        "CATHEDRAL_EXTERNAL_SCORES_SOURCE": SOURCE,
        "CATHEDRAL_EXTERNAL_SCORES_MODE": "blend",
        "CATHEDRAL_EXTERNAL_SCORES_FRACTION": "0.10",
        "CATHEDRAL_EXTERNAL_SCORES_MAX_FRACTION": "0.10",
        "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED": "1",
        "CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS": "3600",
        "CATHEDRAL_WEIGHTS_MODE": "flat_recent",
        "CATHEDRAL_WEIGHTS_WINDOW_HOURS": "24",
        "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS": "filter",
        "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS": "600",
        "CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE": "0",
        "CATHEDRAL_PERMINER_BONUS_MULT": "0",
        "CATHEDRAL_PERMINER_REQUIRE_COLDKEY": "0",
        "CATHEDRAL_PERMINER_SCORING_MODE": "bonus",
        "CATHEDRAL_WEIGHT_POLICY_NETWORK": NETWORK,
        "CATHEDRAL_WEIGHT_POLICY_NETUID": str(NETUID),
        "CATHEDRAL_WEIGHT_POLICY_KEY_ID": KEY_ID,
        "CATHEDRAL_WEIGHT_POLICY_BURN_UID": "",
        "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2": "0",
        "CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS": "1800",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }


def create_positive_epoch(ledger: Ledger, *, generated_at: str) -> tuple[int, dict[str, float]]:
    epoch_id = ledger.begin_epoch(1)
    work = {**BASE_WORK, CONFIDENTIAL_ONLY: 75.0}
    for index, (hotkey, units) in enumerate(work.items()):
        ledger.add_attestation(
            epoch_id,
            hotkey,
            verdict="VERIFIED",
            tee_type="TDX",
            workload="CPU",
            evidence_digest=hashlib.sha256(f"evidence:{hotkey}".encode()).hexdigest(),
        )
        challenge_id = f"launch-positive-{index}"
        ledger.issue_challenge(challenge_id, hotkey, epoch_id)
        ledger.resolve_challenge(
            challenge_id,
            "verified",
            units,
            validator_derived=True,
        )
    scores = ledger.complete_epoch(epoch_id, ALL_HOTKEYS, generated_at=generated_at)
    require(scores["miner-alpha"] == 1.0, "positive ledger report was not max-normalized")
    require(scores[CONFIDENTIAL_ONLY] > 0.0, "positive report lacks compute-only control")
    return epoch_id, scores


def create_zero_epoch(ledger: Ledger, *, generated_at: str) -> tuple[int, dict[str, float]]:
    epoch_id = ledger.begin_epoch(2)
    scores = ledger.complete_epoch(epoch_id, ALL_HOTKEYS, generated_at=generated_at)
    require(set(scores) == set(ALL_HOTKEYS), "zero report is not a complete snapshot")
    require(all(value == 0.0 for value in scores.values()), "zero report retained prior work")
    return epoch_id, scores


def survivor_cases(hotkeys: Sequence[str]) -> list[tuple[str, dict[str, int]]]:
    """Generate every nonempty survivor subset with unique and merged UID cases."""
    ordered = tuple(sorted(set(hotkeys)))
    require(bool(ordered), "signed vector has no hotkeys to audit")
    cases: list[tuple[str, dict[str, int]]] = []
    for size in range(1, len(ordered) + 1):
        for members in itertools.combinations(ordered, size):
            label = "+".join(members)
            unique = {hotkey: 100 + ordered.index(hotkey) for hotkey in members}
            cases.append((f"unique:{label}", unique))
            if len(members) > 1:
                cases.append((f"merged:{label}", {hotkey: 900 for hotkey in members}))
    return cases


def signed_component_ratios(payload: Mapping[str, Any]) -> dict[str, float]:
    ratios: dict[str, float] = {}
    for row in payload.get("weights") or []:
        hotkey = str(row.get("miner_hotkey") or "")
        require(bool(hotkey), "signed row lacks miner_hotkey")
        require(hotkey not in ratios, f"duplicate signed hotkey {hotkey!r}")
        try:
            weight = float(row["weight"])
            base = float(row["base_component"])
            external = float(row["external_component"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LaunchProofError(f"invalid signed components for {hotkey!r}") from exc
        require(weight > 0.0, f"signed row {hotkey!r} has nonpositive weight")
        require(abs(weight - (base + external)) <= 1e-15, f"component sum mismatch for {hotkey!r}")
        ratio = external / weight
        require(
            ratio <= CAP + SIGNED_FRACTION_TOLERANCE,
            f"signed confidential attribution exceeds 10% for {hotkey!r}",
        )
        ratios[hotkey] = ratio
    require(bool(ratios), "signed vector has no component-bearing rows")
    return ratios


def signed_confidential_fraction(payload: Mapping[str, Any]) -> float:
    total_base = 0.0
    total_external = 0.0
    total_weight = 0.0
    for row in payload.get("weights") or []:
        try:
            weight = float(row["weight"])
            base = float(row["base_component"])
            external = float(row["external_component"])
        except (KeyError, TypeError, ValueError) as exc:
            hotkey = str(row.get("miner_hotkey") or "")
            raise LaunchProofError(f"invalid signed components for {hotkey!r}") from exc
        total_weight += weight
        total_base += base
        total_external += external
    require(total_weight > 0.0, "signed vector has zero total weight")
    require(total_base > 0.0, "signed vector has zero base attribution")
    require(
        total_external > 0.0,
        "signed vector has zero confidential attribution after payable filtering",
    )
    fraction = total_external / total_weight
    require(
        math.isclose(fraction, CAP, rel_tol=0.0, abs_tol=SIGNED_FRACTION_TOLERANCE),
        f"signed confidential attribution {fraction:.16f} does not match the 10% target",
    )
    return fraction


def audit_quantized_case(
    payload: Mapping[str, Any],
    hotkey_to_uid: Mapping[str, int],
    *,
    vector_to_uid_weights: Callable[[dict[str, Any], dict[str, int]], dict[int, float]],
    quantize: Callable[[list[int], list[float]], tuple[Sequence[int], Sequence[int]]],
) -> dict[str, Any]:
    """Audit one production drop/merge/renormalize/quantize transform."""
    rows = {str(row["miner_hotkey"]): row for row in payload["weights"]}
    require(set(hotkey_to_uid).issubset(rows), "survivor mapping contains an unsigned hotkey")

    merged: dict[int, dict[str, float]] = {}
    for hotkey, uid in hotkey_to_uid.items():
        row = rows[hotkey]
        state = merged.setdefault(int(uid), {"base": 0.0, "external": 0.0})
        state["base"] += float(row["base_component"])
        state["external"] += float(row["external_component"])

    with contextlib.redirect_stdout(io.StringIO()):
        uid_weights = vector_to_uid_weights(dict(payload), dict(hotkey_to_uid))
    require(set(uid_weights) == set(merged), "thin-validator UID output differs from survivor map")
    ordered = sorted(uid_weights)
    q_uids_raw, q_values_raw = quantize(ordered, [uid_weights[uid] for uid in ordered])
    q_uids = [int(uid) for uid in q_uids_raw]
    q_values = [int(value) for value in q_values_raw]
    require(len(q_uids) == len(q_values), "Bittensor returned mismatched UID/value lengths")
    require(len(q_uids) == len(set(q_uids)), "Bittensor returned duplicate UIDs")
    require(set(q_uids).issubset(merged), "Bittensor returned an unknown UID")
    require(all(value > 0 for value in q_values), "Bittensor returned nonpositive u16 weight")
    total_u16 = sum(q_values)
    require(total_u16 > 0, "Bittensor quantizer returned zero total weight")

    attributed_u16 = 0.0
    max_uid_ratio = 0.0
    for uid, value in zip(q_uids, q_values, strict=True):
        state = merged[uid]
        total_component = state["base"] + state["external"]
        require(total_component > 0.0, f"UID {uid} has no signed component mass")
        ratio = state["external"] / total_component
        require(ratio <= CAP, f"merged UID {uid} exceeds 10% confidential attribution")
        max_uid_ratio = max(max_uid_ratio, ratio)
        attributed_u16 += value * ratio
    realized = attributed_u16 / total_u16
    require(realized <= CAP, "realized u16 confidential attribution exceeds 10%")
    return {
        "input_uids": len(ordered),
        "quantized_uids": len(q_uids),
        "total_u16": total_u16,
        "realized_fraction": realized,
        "max_uid_fraction": max_uid_ratio,
    }


@contextlib.contextmanager
def serve_local_app(app: Any) -> Iterator[str]:
    try:
        import uvicorn
    except ImportError as exc:
        raise LaunchProofError("uvicorn is required for the localhost HTTP proof") from exc

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = int(listener.getsockname()[1])
    config = uvicorn.Config(app, log_level="critical", access_log=False, lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        name="cross-repo-launch-uvicorn",
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10.0
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2.0)
        listener.close()
        raise LaunchProofError("localhost scorer server did not start")
    try:
        yield f"http://127.0.0.1:{port}{Poster.ROUTE}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)
        listener.close()
        require(not thread.is_alive(), "localhost scorer server did not stop")


def seed_base_scorer(store: Any, *, now: datetime) -> None:
    ran_at = _iso_millis(now)

    def write(conn: Any) -> None:
        for index, hotkey in enumerate(BASE_WORK):
            conn.execute(
                "INSERT INTO eval_runs(id, ran_at, eval_output_schema_version, "
                "miner_hotkey, task_type, row_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    f"cross-repo-eval-{index}",
                    ran_at,
                    6,
                    hotkey,
                    "synthetic_boolean_v1",
                    json.dumps({"weighted_score": 1.0}),
                ),
            )
        for uid, hotkey in enumerate(ALL_HOTKEYS, start=10):
            conn.execute(
                "INSERT INTO metagraph_hotkeys(network, netuid, hotkey, uid, coldkey, "
                "block, updated_at_iso) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (NETWORK, NETUID, hotkey, uid, f"cold-{uid}", 1, ran_at),
            )

    store.write(write)


def import_scorer(repo: Path) -> dict[str, Any]:
    require(repo.is_dir(), f"scorer repository does not exist: {repo}")
    require((repo / "scaffold/publisher/app.py").is_file(), "scorer repository lacks app.py")
    sys.path.insert(0, str(repo))
    try:
        from bittensor.utils.weight_utils import convert_and_normalize_weights_and_uids
        from scaffold import validator_thin
        from scaffold.publisher import external_scores, weights
        from scaffold.publisher.app import build_app
    except Exception as exc:
        raise LaunchProofError(f"scorer/Bittensor API import failed: {exc}") from exc
    try:
        bittensor_version = version("bittensor")
    except PackageNotFoundError as exc:
        raise LaunchProofError("installed Bittensor distribution metadata is missing") from exc
    return {
        "build_app": build_app,
        "external_scores": external_scores,
        "weights": weights,
        "validator_thin": validator_thin,
        "quantize": convert_and_normalize_weights_and_uids,
        "bittensor_version": bittensor_version,
    }


def verify_persisted_report(
    store: Any,
    acknowledgement: Mapping[str, Any],
    *,
    epoch: int,
    expected_score_count: int,
) -> dict[str, Any]:
    reports = store.query(
        "SELECT id, epoch, report_sha256, score_count, report_json "
        "FROM external_score_reports WHERE source=? AND epoch=?",
        (SOURCE, epoch),
    )
    require(len(reports) == 1, f"expected one persisted report at epoch {epoch}")
    report = reports[0]
    require(int(report["score_count"]) == expected_score_count, "persisted score count mismatch")
    require(report["report_sha256"] == acknowledgement["report_sha256"], "digest mismatch")
    normalized = json.loads(report["report_json"])
    require(normalized["complete"] is True, "persisted report is not complete")
    require(normalized["report_sha256"] == report["report_sha256"], "normalized digest mismatch")
    entries = store.query(
        "SELECT miner_hotkey, score FROM external_score_entries WHERE report_id=?",
        (report["id"],),
    )
    require(len(entries) == expected_score_count, "persisted entry count mismatch")
    return normalized


def run_proof(scorer_repo: Path) -> dict[str, Any]:
    confidential_repo = Path(__file__).resolve().parents[1]
    scorer_repo = scorer_repo.resolve()
    scorer = import_scorer(scorer_repo)
    build_app = scorer["build_app"]
    external_scores = scorer["external_scores"]
    weights = scorer["weights"]
    validator_thin = scorer["validator_thin"]

    with tempfile.TemporaryDirectory(prefix="cathedral-cross-repo-") as temp_dir:
        temp = Path(temp_dir)
        now = datetime.now(timezone.utc)
        with contextlib.redirect_stdout(io.StringIO()):
            app = build_app(
                database_path=str(temp / "scorer.sqlite"),
                signing_key_hex=SIGNING_KEY_HEX,
            )
        store = app.state.store
        require(store.backend == "sqlite", "launch proof scorer store is not SQLite")
        require(
            Path(store.path).resolve() == (temp / "scorer.sqlite").resolve(),
            "launch proof scorer store escaped the temporary directory",
        )
        seed_base_scorer(store, now=now)
        ledger = Ledger(temp / "confidential.sqlite")
        poster: Poster | None = None
        try:
            with serve_local_app(app) as endpoint:
                poster = Poster(
                    endpoint,
                    BEARER_TOKEN,
                    HMAC_SECRET,
                    allow_http_for_tests=True,
                )
                positive_epoch, positive_scores = create_positive_epoch(
                    ledger,
                    generated_at=_iso_millis(datetime.now(timezone.utc)),
                )
                positive_body = ledger.report_bytes(positive_epoch)
                require(
                    hashlib.sha256(positive_body).hexdigest()
                    == ledger.report_digest(positive_epoch),
                    "ledger frozen-body digest mismatch",
                )
                positive_ack = ledger.post_and_mark_published(positive_epoch, poster)
                require(positive_ack.get("status") == "accepted", "positive report not accepted")
                persisted_positive = verify_persisted_report(
                    store,
                    positive_ack,
                    epoch=1,
                    expected_score_count=len(ALL_HOTKEYS),
                )
                snapshot = external_scores.latest_snapshot_scores(
                    store,
                    source=SOURCE,
                    now=datetime.now(timezone.utc),
                )
                require(snapshot == positive_scores, "positive latest snapshot differs from ledger")

                with contextlib.redirect_stdout(io.StringIO()):
                    signed = weights.build_signed_vector(
                        store,
                        signing_key_hex=SIGNING_KEY_HEX,
                        now=datetime.now(timezone.utc),
                    )
                validator_thin.accept_vector(
                    signed,
                    public_key_hex=app.state.public_key_hex,
                    key_id=KEY_ID,
                    network=NETWORK,
                    netuid=NETUID,
                    fence_version=0,
                )
                ratios = signed_component_ratios(signed)
                aggregate_fraction = signed_confidential_fraction(signed)
                require(CONFIDENTIAL_ONLY not in ratios, "confidential-only hotkey received weight")
                require(
                    set(ratios) == set(BASE_WORK), "signed vector differs from base-payable miners"
                )

                cases = survivor_cases(tuple(ratios))
                audits = [
                    audit_quantized_case(
                        signed,
                        mapping,
                        vector_to_uid_weights=validator_thin.vector_to_uid_weights,
                        quantize=scorer["quantize"],
                    )
                    for _, mapping in cases
                ]

                zero_epoch, _zero_scores = create_zero_epoch(
                    ledger,
                    generated_at=_iso_millis(datetime.now(timezone.utc)),
                )
                zero_ack = ledger.post_and_mark_published(zero_epoch, poster)
                require(zero_ack.get("status") == "accepted", "zero report not accepted")
                persisted_zero = verify_persisted_report(
                    store,
                    zero_ack,
                    epoch=2,
                    expected_score_count=len(ALL_HOTKEYS),
                )
                zero_snapshot = external_scores.latest_snapshot_scores(
                    store,
                    source=SOURCE,
                    now=datetime.now(timezone.utc),
                )
                require(zero_snapshot == {}, "latest complete zero report did not revoke scores")
                blend_meta: dict[str, Any] = {}
                with contextlib.redirect_stdout(io.StringIO()):
                    after_zero = weights.compose_scores(
                        store,
                        now=datetime.now(timezone.utc),
                        blend_meta_out=blend_meta,
                    )
                require(set(after_zero) == set(BASE_WORK), "zero report changed base miner set")
                require(
                    all(value == 1.0 for value in after_zero.values()),
                    "zero report changed base scores",
                )
                require(not blend_meta.get("blended"), "zero report retained confidential blend")
                require(CONFIDENTIAL_ONLY not in after_zero, "revoked compute-only hotkey survived")

            persisted_reports = store.query(
                "SELECT epoch FROM external_score_reports WHERE source=? ORDER BY epoch",
                (SOURCE,),
            )
            require(
                [int(row["epoch"]) for row in persisted_reports] == [1, 2],
                "latest-wins history mismatch",
            )
            return {
                "status": "PASS",
                "bittensor_version": scorer["bittensor_version"],
                "quantizer": (f"{scorer['quantize'].__module__}.{scorer['quantize'].__name__}"),
                "confidential_commit": _git_head(confidential_repo),
                "scorer_commit": _git_head(scorer_repo),
                "http_reports_accepted": 2,
                "ledger_epochs": 2,
                "persisted_reports": len(persisted_reports),
                "positive_entries": len(persisted_positive["scores"]),
                "zero_entries": len(persisted_zero["scores"]),
                "signed_vectors": 1,
                "signed_rows": len(signed["weights"]),
                "survivor_cases": len(cases),
                "quantized_uid_rows": sum(audit["quantized_uids"] for audit in audits),
                "aggregate_signed_confidential_fraction": aggregate_fraction,
                "max_signed_confidential_fraction": max(ratios.values()),
                "max_u16_confidential_fraction": max(
                    audit["realized_fraction"] for audit in audits
                ),
                "confidential_only_weight": 0.0,
                "zero_revocation": True,
            }
        finally:
            ledger.close()
            store.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorer-repo", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        with temporary_environment(scorer_environment()):
            summary = run_proof(args.scorer_repo)
    except BaseException as exc:
        failure = {"status": "FAIL", "error_type": type(exc).__name__, "error": str(exc)}
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
