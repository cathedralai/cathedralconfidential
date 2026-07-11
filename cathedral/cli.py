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
import json
from pathlib import Path

from cathedral import census as census_mod
from cathedral.api import WorkQueue
from cathedral.common import Policy
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem

DEFAULT_QUEUE_FILE = Path(".cathedral_queue.json")


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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
