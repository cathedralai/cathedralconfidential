"""Cathedral operator CLI (docs/DESIGN.md §7, §10).

Thin argparse front-end over the in-process control plane (cathedral.api),
the SAT lane (cathedral.lanes.sat), and the shared Policy check
(cathedral.common). No hardware, no network: ``census`` shells into the
existing CC probe, ``verify-quote`` is a client-side policy check against a
caller-supplied (mocked) measurement/tcb pair, and ``work submit`` / ``work
status`` drive a WorkQueue backed by the SAT lane's canonical backfill.
Pending customer jobs persist across invocations in a small JSON queue file
so ``submit`` and ``status`` compose naturally from the shell.

Every subcommand is a plain, importable function taking parsed args and
returning an int exit code -- callers (tests, scripts) never need to shell
out.

    python -m cathedral.cli census
    python -m cathedral.cli verify-quote --measurement M --allowed-measurement M --tcb 3 --min-tcb 1
    python -m cathedral.cli work submit --n-vars 3 --clauses '[[1, 2, -3]]'
    python -m cathedral.cli work status
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path

from cathedral import census as census_mod
from cathedral.api import WorkQueue
from cathedral.common import Policy
from cathedral.enroll import RegistryStore
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.poster import Poster
from cathedral.runtime import (
    ConfidentialRuntime,
    EpochRun,
    MinerOutcome,
    MinerTarget,
    RuntimeConfig,
)
from cathedral.worker import WorkerServer

DEFAULT_QUEUE_FILE = Path(".cathedral_queue.json")
DEFAULT_PUBLISHER_BEARER_ENV = "CATHEDRAL_PUBLISHER_BEARER_TOKEN"
DEFAULT_PUBLISHER_HMAC_ENV = "CATHEDRAL_PUBLISHER_HMAC_SECRET"


# --------------------------------------------------------------------------
# work-queue persistence: a JSON file holding pending customer SAT jobs, so
# separate `work submit` / `work status` invocations see the same state.
# --------------------------------------------------------------------------


def _queue_path(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "queue_file", None) or DEFAULT_QUEUE_FILE)


def _load_pending(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as fh:
        return json.load(fh)


def _save_pending(path: Path, pending: list[dict]) -> None:
    with path.open("w") as fh:
        json.dump(pending, fh)


def _item_to_dict(item: SatWorkItem) -> dict:
    return {
        "n_vars": item.instance.n_vars,
        "clauses": item.instance.clauses,
        "seed": item.seed,
        "challenge_id": item.challenge_id,
    }


def _dict_to_item(d: dict) -> SatWorkItem:
    instance = SatInstance(n_vars=d["n_vars"], clauses=d["clauses"])
    # Legacy queue entries may lack challenge_id; recompute and validate.
    stored_id = d.get("challenge_id")
    computed_id = _compute_challenge_id(instance, d["seed"])
    if stored_id is not None and stored_id != computed_id:
        raise ValueError(
            f"persisted challenge_id {stored_id} does not match "
            f"recomputed {computed_id} for seed={d['seed']}"
        )
    return SatWorkItem(instance=instance, seed=d["seed"], challenge_id=computed_id)


def _build_queue(pending: list[dict]) -> WorkQueue:
    """A WorkQueue preloaded with persisted customer jobs, backfilled by SatLane."""

    lane = SatLane()
    queue = WorkQueue(backfill=lambda: lane.dispatch("cli", budget=1))
    for d in pending:
        queue.enqueue(_dict_to_item(d))
    return queue


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def cmd_census(args: argparse.Namespace) -> int:
    return census_mod.main()


def cmd_verify_quote(args: argparse.Namespace) -> int:
    policy = Policy(allowed_measurements=set(args.allowed_measurement), min_tcb=args.min_tcb)
    ok = args.measurement in policy.allowed_measurements and args.tcb >= policy.min_tcb
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def cmd_work_submit(args: argparse.Namespace) -> int:
    path = _queue_path(args)
    pending = _load_pending(path)
    queue = _build_queue(pending)

    if args.clauses is not None:
        clauses = json.loads(args.clauses)
        instance = SatInstance(n_vars=args.n_vars, clauses=clauses)
        seed = args.seed or 0
        challenge_id = _compute_challenge_id(instance, seed)
        item = SatWorkItem(instance=instance, seed=seed, challenge_id=challenge_id)
    else:
        # No explicit job given: backfill one canonical instance to submit.
        dispatched = SatLane().dispatch("cli-submit", budget=1)
        assert isinstance(dispatched, SatWorkItem)
        item = dispatched

    queue.enqueue(item)
    pending.append(_item_to_dict(item))
    _save_pending(path, pending)
    print(f"submitted job (n_vars={item.instance.n_vars}, seed={item.seed}); queue depth={len(pending)}")
    return 0


def cmd_work_status(args: argparse.Namespace) -> int:
    path = _queue_path(args)
    pending = _load_pending(path)
    print(f"customer jobs queued : {len(pending)}")
    print(f"next claim source    : {'customer' if pending else 'backfill (canonical)'}")
    return 0


def _load_json(path: str, description: str) -> object:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load {description} file") from exc


def _load_policy(path: str) -> Policy:
    raw = _load_json(path, "measurements")
    if isinstance(raw, list):
        measurements = raw
        min_tcb = 0
    elif isinstance(raw, dict):
        measurements = raw.get("allowed_measurements")
        min_tcb = raw.get("min_tcb", 0)
    else:
        raise ValueError("measurements file must be a JSON array or object")
    if not isinstance(measurements, list) or any(
        not isinstance(value, str) or not value for value in measurements
    ):
        raise ValueError("allowed_measurements must be a list of nonempty strings")
    if isinstance(min_tcb, bool) or not isinstance(min_tcb, int) or min_tcb < 0:
        raise ValueError("min_tcb must be a nonnegative integer")
    return Policy(allowed_measurements=set(measurements), min_tcb=min_tcb)


def _load_tokens(path: str | None) -> dict[str, str]:
    if path is None:
        return {}
    raw = _load_json(path, "token mapping")
    if not isinstance(raw, dict) or any(
        not isinstance(hotkey, str)
        or not hotkey
        or not isinstance(token, str)
        or not token
        for hotkey, token in raw.items()
    ):
        raise ValueError("token mapping must map hotkeys to nonempty strings")
    return dict(raw)


def _publisher_from_args(args: argparse.Namespace) -> Poster | None:
    endpoint = getattr(args, "publisher_endpoint", None)
    if endpoint is None:
        return None
    bearer_env = args.publisher_bearer_env
    hmac_env = args.publisher_hmac_env
    bearer = os.environ.get(bearer_env)
    secret = os.environ.get(hmac_env)
    if not bearer or not secret:
        raise ValueError(
            f"publisher credentials must be set in {bearer_env} and {hmac_env}"
        )
    return Poster(endpoint, bearer, secret)


def _build_runtime(args: argparse.Namespace) -> tuple[ConfidentialRuntime, Ledger, dict[str, str]]:
    tokens = _load_tokens(getattr(args, "tokens_file", None))
    config = RuntimeConfig(
        miner_timeout_seconds=getattr(args, "miner_timeout_seconds", 10.0),
        miner_attempts=getattr(args, "miner_attempts", 2),
        max_workers=getattr(args, "max_workers", 8),
        production_mode=not getattr(args, "development", False),
        allow_insecure_http_for_tests=getattr(args, "development", False),
    )
    ledger = Ledger(args.ledger_db)
    measurements_file = getattr(args, "measurements_file", None)
    runtime = ConfidentialRuntime(
        RegistryStore(getattr(args, "registry_db", ":memory:")),
        ledger,
        _load_policy(measurements_file) if measurements_file else Policy(),
        _publisher_from_args(args),
        token_provider=tokens.get,
        config=config,
    )
    return runtime, ledger, tokens


def _target(args: argparse.Namespace, tokens: dict[str, str]) -> MinerTarget:
    return MinerTarget(args.canary_hotkey, args.canary_endpoint, tokens.get(args.canary_hotkey))


def _outcome_json(outcome: MinerOutcome) -> dict[str, object]:
    return {
        "hotkey": outcome.hotkey,
        "endpoint_url": outcome.endpoint_url,
        "status": outcome.status,
        "admitted": outcome.admitted,
        "challenge_id": outcome.challenge_id,
        "work_units": outcome.work_units,
        "score": outcome.score,
        "error": outcome.error,
    }


def _run_json(run: EpochRun) -> dict[str, object]:
    return {
        "epoch_id": run.epoch_id,
        "source_epoch": run.source_epoch,
        "status": run.status,
        "published": run.published,
        "scores": dict(run.scores),
        "outcomes": [_outcome_json(outcome) for outcome in run.outcomes],
    }


def cmd_worker_serve(args: argparse.Namespace) -> int:
    try:
        is_loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        is_loopback = args.host == "localhost"
    if not is_loopback and not args.development_allow_non_loopback:
        raise ValueError(
            "plain worker HTTP must bind loopback unless development mode is explicit"
        )
    token = os.environ.get(args.bearer_token_env) if args.bearer_token_env else None
    with WorkerServer(
        args.host,
        args.port,
        configured_hotkey=args.hotkey,
        bearer_token=token,
        allow_non_loopback_for_development=args.development_allow_non_loopback,
    ) as server:
        print(json.dumps({"host": server.host, "port": server.port, "hotkey": args.hotkey}))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


def cmd_runtime_canary(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args)
    try:
        outcome = runtime.check_canary(_target(args, tokens))
        print(json.dumps(_outcome_json(outcome), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_run_epoch(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args)
    try:
        run = runtime.run_epoch(
            args.source_epoch,
            _target(args, tokens),
            publish=args.publish,
        )
        print(json.dumps(_run_json(run), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_status(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        print(json.dumps(dict(runtime.status()), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_retry_publish(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        acknowledgement = runtime.publish_completed(args.epoch_id)
        print(json.dumps(dict(acknowledgement), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_abort_running(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        epoch_id = runtime.abort_running()
        print(json.dumps({"aborted_epoch_id": epoch_id}, sort_keys=True))
        return 0
    finally:
        ledger.close()


# --------------------------------------------------------------------------
# argparse wiring
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral", description="Cathedral operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_census = sub.add_parser("census", help="run the local CC capability probe")
    p_census.add_argument(
        "--json", action="store_true", help="machine-readable output (passed through to cathedral.census)"
    )
    p_census.set_defaults(func=cmd_census)

    p_verify = sub.add_parser("verify-quote", help="check a mock attested quote against a policy")
    p_verify.add_argument("--measurement", required=True, help="the (mock) attested measurement")
    p_verify.add_argument("--tcb", type=int, required=True, help="the (mock) attested tcb version")
    p_verify.add_argument(
        "--allowed-measurement",
        action="append",
        required=True,
        dest="allowed_measurement",
        help="repeatable; one or more measurements the policy allows",
    )
    p_verify.add_argument("--min-tcb", type=int, default=0)
    p_verify.set_defaults(func=cmd_verify_quote)

    p_work = sub.add_parser("work", help="drive the SAT-lane work queue")
    work_sub = p_work.add_subparsers(dest="work_command", required=True)

    p_submit = work_sub.add_parser("submit", help="enqueue a customer job")
    p_submit.add_argument("--n-vars", type=int, default=0, help="variable count (paired with --clauses)")
    p_submit.add_argument(
        "--clauses",
        default=None,
        help="JSON list of clauses (DIMACS ints); omit to submit canonical backfill work",
    )
    p_submit.add_argument("--seed", type=int, default=None)
    p_submit.add_argument("--queue-file", default=None, help=f"default: {DEFAULT_QUEUE_FILE}")
    p_submit.set_defaults(func=cmd_work_submit)

    p_status = work_sub.add_parser("status", help="report queue/backfill state")
    p_status.add_argument("--queue-file", default=None, help=f"default: {DEFAULT_QUEUE_FILE}")
    p_status.set_defaults(func=cmd_work_status)

    p_worker = sub.add_parser("worker", help="run a miner worker")
    worker_sub = p_worker.add_subparsers(dest="worker_command", required=True)
    p_serve = worker_sub.add_parser("serve", help="serve one configured miner hotkey")
    p_serve.add_argument("--hotkey", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8081)
    p_serve.add_argument("--bearer-token-env", default=None)
    p_serve.add_argument("--development-allow-non-loopback", action="store_true")
    p_serve.set_defaults(func=cmd_worker_serve)

    p_runtime = sub.add_parser("runtime", help="operate confidential TDX report epochs")
    runtime_sub = p_runtime.add_subparsers(dest="runtime_command", required=True)

    def add_runtime_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--registry-db", required=True)
        command.add_argument("--ledger-db", required=True)
        command.add_argument("--measurements-file", required=True)
        command.add_argument("--tokens-file", default=None)
        command.add_argument("--miner-timeout-seconds", type=float, default=10.0)
        command.add_argument("--miner-attempts", type=int, default=2)
        command.add_argument("--max-workers", type=int, default=8)
        command.add_argument("--development", action="store_true")
        command.add_argument("--publisher-endpoint", default=None)
        command.add_argument(
            "--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV
        )
        command.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)

    def add_canary(command: argparse.ArgumentParser) -> None:
        command.add_argument("--canary-hotkey", required=True)
        command.add_argument("--canary-endpoint", required=True)

    p_canary = runtime_sub.add_parser("canary", help="run fresh TDX and canonical SAT canary")
    add_runtime_common(p_canary)
    add_canary(p_canary)
    p_canary.set_defaults(func=cmd_runtime_canary)

    p_run = runtime_sub.add_parser("run-epoch", help="freeze one complete report")
    add_runtime_common(p_run)
    add_canary(p_run)
    p_run.add_argument("--source-epoch", type=int, required=True)
    p_run.add_argument("--publish", action="store_true")
    p_run.set_defaults(func=cmd_runtime_run_epoch)

    p_runtime_status = runtime_sub.add_parser("status", help="show restart-blocking state")
    p_runtime_status.add_argument("--ledger-db", required=True)
    p_runtime_status.set_defaults(func=cmd_runtime_status)

    p_retry = runtime_sub.add_parser("retry-publish", help="publish frozen report bytes")
    p_retry.add_argument("--ledger-db", required=True)
    p_retry.add_argument("--publisher-endpoint", required=True)
    p_retry.add_argument(
        "--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV
    )
    p_retry.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)
    p_retry.add_argument("--epoch-id", type=int, required=True)
    p_retry.set_defaults(func=cmd_runtime_retry_publish)

    p_abort = runtime_sub.add_parser("abort-running", help="abort the running epoch")
    p_abort.add_argument("--ledger-db", required=True)
    p_abort.set_defaults(func=cmd_runtime_abort_running)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(json.dumps({"error": str(exc)[:300]}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
