# BUILD_SPEC — Cathedral testable core

This spec hands five modules to five implement agents. The interfaces
(`cathedral/lanes/__init__.py`, `cathedral/lanes/sat_types.py`) and the pytest
suite under `tests/` are **frozen contracts** — implementers satisfy them and
**must not modify the tests**.

## Ground rules (all modules)

- Python 3.11+, **standard library only**. Dev-only third-party dep: `pytest`.
- No network, no hardware, no TEE/vendor calls. Attestation is **mocked** behind
  the real `verify()` interface. Any hardware path stays a Phase-1 stub.
- Super thin, rock solid: small, readable, no cleverness. Match existing style
  (`from __future__ import annotations`, module docstring citing `docs/DESIGN.md`,
  frozen dataclasses for data).
- Do **not** touch `cathedral/census.py`. Do **not** change signatures in
  `cathedral/common.py` (adding dataclasses is allowed but none is required).
- Import shared types from `cathedral.common` and `cathedral.lanes`. Do not
  redefine `Tier`, `Attested`, `Evidence`, `Policy`, `issue_nonce`, `report_data`.

## Frozen shared interfaces (already written — do not edit)

`cathedral/lanes/__init__.py`

```python
class WorkItem: ...          # marker base
class Certificate: ...       # marker base

class Lane(abc.ABC):
    name: str
    def qualify(self, attested: Attested) -> bool: ...
    def dispatch(self, miner: str, budget: int) -> WorkItem: ...
    def verify(self, item: WorkItem, result: object) -> Certificate | None: ...
    def score(self, miner: str, certs: list[Certificate]) -> float: ...

ROUTING_VECTOR: dict[str, float]     # lane -> emission share
```

`cathedral/lanes/sat_types.py`

```python
@dataclass(frozen=True) class SatInstance:    n_vars: int; clauses: list[list[int]]
@dataclass(frozen=True) class SatWorkItem(WorkItem):    instance: SatInstance; seed: int
@dataclass(frozen=True) class SatCertificate(Certificate):
    satisfiable: bool; assignment: list[int] | None; work_units: float
```

DIMACS convention: vars 1..n_vars; literal +v/−v; clause = OR of literals;
`assignment` = complete list of signed literals (one per var).

---

## File ownership

| Agent | File | Tests that pin it |
|---|---|---|
| A | `cathedral/lanes/sat.py` | `tests/test_sat_lane.py`, `tests/test_skeleton.py` |
| B | `cathedral/economics.py` | `tests/test_economics.py`, `tests/test_skeleton.py` |
| C | `cathedral/api.py` | `tests/test_api.py` |
| D | `cathedral/cli.py` | (no dedicated test — smoke-importable; see below) |
| E | `cathedral/verify/mock.py` | `tests/test_verify_mock.py`, `tests/test_skeleton.py` |

`tests/test_census.py` and `tests/test_binding.py` already pass against the
existing `census.py` / `common.py`; do not change those modules to satisfy them.

---

## A — `cathedral/lanes/sat.py`

`class SatLane(Lane)` plus a module-level pure-Python solver.

- `name = "sat_benchmark"` (must match `ROUTING_VECTOR` key).
- `qualify(attested) -> bool`: True iff `attested.tier in {Tier.CC_CPU_SNP,
  Tier.CC_CPU_TDX}` (big-core CPU enclaves). CC_GPU does **not** qualify.
- `dispatch(miner, budget) -> SatWorkItem`: if an internal customer queue holds
  an instance, wrap and return it; else generate **canonical** work from a
  deterministic seed (a monotonic counter or a hash of `miner` — implementer's
  choice, but the returned `SatWorkItem.seed` must regenerate the same
  `instance`). Canonical instances are **satisfiable by construction**: plant a
  random assignment, then emit clauses that each include ≥1 literal true under
  it. This guarantees every backfilled job has a findable certificate.
- `verify(item, result) -> SatCertificate | None`:
  - `result.satisfiable is True`: accept iff `result.assignment` is non-None and
    satisfies **every** clause of `item.instance` (self-certifying assignment
    check — O(#literals), no solving). Reject (return None) a forged/insufficient
    assignment.
  - `result.satisfiable is False`: verify the UNSAT claim. **Testable core:**
    re-run `solve_sat(item.instance)`; accept iff it returns None, reject if a
    satisfying assignment exists (a false UNSAT claim). *(Phase-2 replaces the
    re-solve with a DRAT proof carried in the certificate; document this.)*
  - On accept, return the certificate; on any failure, return None.
- `score(miner, certs) -> float`: `sum(c.work_units for c in certs)`.
- `solve_sat(instance: SatInstance) -> list[int] | None`: a small, deterministic
  **DPLL** (unit propagation + first-unassigned-var branch, try True then
  False). Returns a **complete** satisfying assignment (free vars defaulted, e.g.
  positive) or None if UNSAT. Used to *produce* assignments and to check UNSAT
  claims; it is **not** used on the satisfiable-accept path.

## B — `cathedral/economics.py`

`apply_routing(lane_scores, routing, floor) -> (weights, burn)`

- `lane_scores: dict[str, dict[str, float]]` — `{lane_name: {miner: score}}`.
  The **admitted-miner set** is the union of miners across all lanes; admit an
  idle miner by including it with score `0.0` in some lane.
- `routing: dict[str, float]` — lane emission shares (need not sum to 1).
- `floor: float` — total fraction reserved for the attestation floor layer.
- Returns `(weights: dict[str, float], burn: float)`.

Three-layer emission, **sum-conserving to exactly 1.0**:

1. **Floor layer** (total `floor`): split equally among admitted miners
   (`floor / n_admitted` each). If there are no admitted miners, the whole floor
   burns.
2. **Work layer** (total `1 - floor`): let `denom = sum(routing.values())`. Each
   lane `L` gets budget `(1 - floor) * routing[L] / denom`. Within a lane, miner
   `m` gets `lane_budget * score_m / total_score`. If a lane's total score is 0
   (or the lane is absent from `lane_scores`), its whole budget **burns**.
3. **Burn**: `burn = 1.0 - sum(weights.values())`.

Invariants the tests assert: `sum(weights.values()) + burn == 1.0` (±1e-9); zero
total work ⇒ `weights` sum to `floor` and `burn == 1 - floor`; raising a lane's
routing share raises that lane's miners' weight.

## C — `cathedral/api.py`

Plain in-process control plane. **No HTTP server.** Pure, directly-unit-testable
classes.

- `class WorkQueue`:
  - `__init__(self, backfill: Callable[[], WorkItem])` — `backfill` produces
    canonical work on demand.
  - `enqueue(self, item: WorkItem) -> None` — add a customer job (FIFO).
  - `claim(self) -> WorkItem` — pop the oldest customer job if any, else return
    `self.backfill()` (canonical backfill). Never returns None.
- `class Inventory`:
  - `register(self, uid: str, attested: Attested) -> None`.
  - `get(self, uid) -> Attested | None`; `items(self) -> Iterable[(uid, Attested)]`.
  - `by_tier(self, tier: Tier) -> list[str]` — uids whose attested tier matches.
- `@dataclass(frozen=True) class Request`: `tier: Tier | None = None`,
  `lane: object | None = None` (anything exposing `.qualify(attested)->bool`).
- `class Allocator`:
  - `__init__(self, inventory: Inventory)`.
  - `candidates(self, request: Request) -> list[str]`: uids that satisfy the
    request — if `request.lane` is set, those whose attested passes
    `lane.qualify`; elif `request.tier` is set, those matching the tier.
  - `allocate(self, request: Request) -> str | None`: first candidate, else None.

## D — `cathedral/cli.py`

`argparse` CLI with **importable** command functions so tests/callers never
shell out. Subcommands:

- `census` — call `cathedral.census.main()`.
- `verify-quote` — client-side stub: check a **mock** `Attested` against a
  `Policy` (`measurement in policy.allowed_measurements` and
  `tcb >= policy.min_tcb`). Prints pass/fail; returns exit code 0/1.
- `work submit` — enqueue a job onto a `WorkQueue`.
- `work status` — report queue/backfill state.

Provide `build_parser() -> argparse.ArgumentParser`, `main(argv=None) -> int`,
and one function per subcommand (e.g. `cmd_census`, `cmd_verify_quote`,
`cmd_work_submit`, `cmd_work_status`) taking parsed args and returning an int
exit code. Keep all business logic in the functions; `main` only parses and
dispatches.

## E — `cathedral/verify/mock.py`

**MOCK — the hardware verifier is Phase 1.** Same *interface* as
`cathedral/verify/__init__.py:verify`, but skips vendor crypto while performing
the real policy + binding checks with `cathedral.common` logic.

- `@dataclass(frozen=True) class MockEvidence`: `kind: EvidenceKind`,
  `tier: Tier`, `chip_id: str`, `measurement: str`, `tcb: int`,
  `miner_hotkey: str`, `bound_report_data: bytes`, `ssh_host_key: bytes | None
  = None`. `bound_report_data` stands in for the report_data the enclave would
  have sealed into a real quote.
- Generators (compute `bound_report_data = report_data(nonce, hotkey,
  ssh_host_key)` so output is always well-formed):
  - `mock_evidence(nonce, hotkey, *, kind, tier, chip_id, measurement, tcb,
    ssh_host_key=None) -> MockEvidence`.
  - Fixtures with **distinct default chip_ids** and matching tier/kind:
    `mock_snp(nonce, hotkey, chip_id=..., measurement=..., tcb=..., ssh_host_key=None)`,
    `mock_tdx(...)`, `mock_gpu(...)`. Callers read `.measurement`/`.tcb` off the
    returned object to build policies (don't hardcode the constants).
- `verify_mock(evidence: MockEvidence, nonce: bytes, policy: Policy) -> Attested
  | None`:
  1. `expected = report_data(nonce, evidence.miner_hotkey,
     evidence.ssh_host_key)`; return None if `evidence.bound_report_data !=
     expected` (freshness + hotkey binding; defeats evidence relay).
  2. Return None if `evidence.measurement not in policy.allowed_measurements`.
  3. Return None if `evidence.tcb < policy.min_tcb`.
  4. Else return `Attested(tier, chip_id, measurement, tcb)`.

Sybil dedup is **free** and lives at admission (validator / test): two evidences
with the same `chip_id` both verify, but keying admitted miners by `chip_id`
collapses them to one UID. `verify_mock` itself does not dedup.

---

## Integration (test_skeleton)

The skeleton test composes E → C → A → B as a one-epoch validator with **no**
new orchestration module: issue a nonce per miner, `verify_mock` its mock
evidence, register the `Attested` in an `Inventory`, run the SAT lane
(`dispatch` → `solve_sat` → build `SatCertificate` → `verify` → `score`), then
`apply_routing` the per-lane scores and assert weights + burn conserve to ~1.0.
`cathedral/neuron/validator.py` stays a Phase-1 stub; wiring lives in the test.

## Done means

`pytest -q` is green with only the five modules above added (plus the two
already-passing census/binding tests). No file outside your assigned module —
and never a test file — is edited to get there.
