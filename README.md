# Cathedral

**Confidential compute for Bittensor. Attestation is admission. Verified work is the score.**

Cathedral is a standalone confidential-compute mechanism. Independently
operated Intel TDX machines prove, cryptographically, that they run inside a
genuine Trusted Execution Environment. That attestation admits a worker. It
never pays. Emissions come only from work the validator dispatches, verifies,
and scores itself. Missing, stale, failed, or revoked work receives an explicit
zero.

Cathedral owns its complete score vector. It does not share emissions with a
second scoring mechanism.

- **Production target:** Bittensor SN39.
- **Current proof:** a testnet SN292 dry run on real Intel TDX hardware. Chain
  broadcast is not yet live. See [`BUILD_STATUS.md`](BUILD_STATUS.md).

## How It Works

1. A worker enrolls a registered hotkey and an authenticated worker endpoint.
2. Cathedral issues a fresh nonce and verifies the worker's Intel TDX quote:
   measurement, TCB, platform policy, and hotkey binding.
3. Attestation grants admission only. A worker with no verified work earns zero.
4. Cathedral dispatches deterministic audit work, verifies delivery, and derives
   the credit itself. Workers never declare their own score.
5. Cathedral freezes and signs one complete compute vector per epoch, including
   explicit zeros that revoke stale credit.
6. A dedicated Cathedral validator verifies the signed vector, requires every
   hotkey to map exactly once to the current metagraph, and submits weights.

## What Is Proven Today

- Real Intel TDX quote collection and external DCAP / Trust Authority
  verification on live hardware, with fresh 8000-byte quotes.
- Fresh-nonce, measurement, TCB, and platform policy enforced at admission.
- Deterministic validator-dispatched audit work as the scored workload:
  60-second epochs, 20 validator-derived work units, score 1.0.
- A signed, complete compute vector with explicit zeros for missing, failed,
  stale, and revoked workers.
- A dedicated Cathedral validator that maps the worker hotkey to UID 41 and
  computes UID 41 = 1.0 in a dry run.

Chain broadcast is not yet live because the validator hotkey is not registered
on testnet SN292. Registration, one monitored `set_weights`, and a subsequent
zero-revocation check remain before the testnet chain gate is complete.

## Roadmap

Future product direction, not yet scored on chain:

- Customer jobs, long-running agents, inference, and evaluation as scored
  workloads.
- Confidential GPU workloads (NVIDIA H100/H200 in CC mode); B200-class later.
- AMD SEV-SNP as a second CPU platform. Quote parsing and cryptographic
  verification exist in-repo; runtime scoring is not yet enabled.

## Hardware

| Hardware | Status |
|---|---|
| Intel TDX CPU | Proven launch path |
| AMD SEV-SNP CPU | Planned second platform (crypto exists, scoring not enabled) |
| NVIDIA H100/H200 CC | Planned |
| NVIDIA B200-class | Planned |

Attestation grants admission. Emissions come from verified delivery.

## Mining

Workers serve confidential compute from their own infrastructure. Cathedral
never requires root access or operator SSH. The scored workload today is
deterministic validator-dispatched audit work.

```bash
cathedral worker --help
cathedral work status
```

## Validating

The dedicated Cathedral validator consumes the signed compute vector. It
verifies signature and freshness, requires a complete hotkey-to-UID mapping,
rejects identity conflicts, and fails closed. It submits the resulting weight
vector only when its hotkey is registered and chain broadcast is enabled.

```bash
cathedral runtime --help
```

## Run Locally

Hardware-free core. Requires Python 3.11+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q            # 469 passed, 3 skipped
```

The hardware-free suite exercises TDX policy verification, signed enrollment,
authenticated workers, deterministic audit work, validator-derived accounting,
complete score reports, and zero revocation. Attestation crypto is mocked behind
the real `verify()` interface; the real Intel TDX path runs on hardware (see
[`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md)).

## Documentation

- [`BUILD_STATUS.md`](BUILD_STATUS.md) - canonical launch evidence and testnet boundary
- [`docs/DESIGN.md`](docs/DESIGN.md) - protocol and scoring design
- [`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md) - Intel TDX attestation path
- [`HANDOFF.md`](HANDOFF.md) - commissioning and test handoff
- [`RUNTEST.md`](RUNTEST.md) - test commands

## License

MIT
