# RUNTEST — Cathedral testable core

Hardware-free, stdlib-only. The only third-party dependency is `pytest` (dev).
No network, no TEE, no hardware: attestation is **mocked** behind the real
`verify()` interface (see `cathedral/verify/mock.py` and `docs/DESIGN.md §6`).

## 1. Create the venv and install

Requires Python 3.11+.

```bash
cd /home/user/cathedral
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'   # installs the package + pytest
```

`-e '.[dev]'` puts `cathedral` on the path (so `scripts/` and console entry
points import cleanly) and pulls in `pytest`. No runtime deps beyond the stdlib.

## 2. Run the test suite

```bash
.venv/bin/python -m pytest -q
```

Expected:

```
44 passed, 1 skipped
```

The skipped test is the hardware-gated TDX round trip in
`tests/test_attest_tdx_hw.py`; it only runs on a TDX CVM when
`CATHEDRAL_RUN_TDX_HW=1` and verifier env vars are set.

## 3. Run the SAT demo

Dispatches a SAT instance, solves it, verifies the self-certifying certificate,
and prints `PASS`:

```bash
.venv/bin/python scripts/demo_sat.py
```

Expected output (assignment varies with the canonical seed):

```
dispatched SAT instance: seed=0 n_vars=8 n_clauses=20
miner returned: satisfiable=True assignment=[...] work_units=20.0
certificate verified; lane score=20.0
PASS
```

## 4. Optional: one full mock epoch

The validator neuron composes the whole path (MOCK-attest → sybil-dedup by
`chip_id` → SAT lane → emission routing) hardware-free:

```bash
.venv/bin/python -c "
from cathedral.neuron.validator import epoch
from cathedral.neuron.miner import MockMiner
from cathedral.common import Policy
miners = [MockMiner('uid-1','hk-1',chip_id='chip-1'),
          MockMiner('uid-2','hk-2',chip_id='chip-2')]
r = epoch(miners, Policy(allowed_measurements={'mock-measurement-0'}))
print('admitted', r.admitted); print('weights', r.weights); print('burn', r.burn)
"
```

## Console entry points (installed by step 1)

- `cathedral` — operator CLI (`census`, `verify-quote`, `work submit/status`)
- `cathedral-census` — the CC capability probe
- `cathedral-validator` / `cathedral-miner` — neuron entry points; `main()` is a
  Phase-1 stub (real chain + hardware attestation), the importable `epoch()` /
  `MockMiner` run the hardware-free core.
