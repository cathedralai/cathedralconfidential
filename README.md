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

- **Production:** Bittensor mainnet SN39. The confidential validator is live and
  submits the complete compute vector on chain.
- **Testing:** Bittensor testnet SN292. It remains the non-paying integration
  lane for proving worker setup, attestation, work, scoring, and UID mapping.

SN39 currently has no eligible confidential miners, so its signed zero-supply
fallback assigns the complete vector to burn UID 0. See
[`BUILD_STATUS.md`](BUILD_STATUS.md) for current evidence.

## Start Mining

The current miner path is an operator-assisted Intel TDX beta. Register on
mainnet SN39 to compete for live emissions, or use testnet SN292 to prove the
same setup without emissions. Follow **[Mining Cathedral](MINING.md)** for
hardware requirements, hotkey registration, worker setup, a real-quote smoke
test, enrollment, acceptance signals, and troubleshooting.

```bash
cathedral worker serve --help
```

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
- On testnet SN292, a dedicated Cathedral validator maps the proven worker
  hotkey to UID 41 and computes UID 41 = 1.0 in a dry run.
- On mainnet SN39, the production validator submitted its first confidential
  vector at block 8614435. With no eligible miners, the on-chain vector has one
  nonzero destination: burn UID 0 = 1.0.

Mainnet chain broadcast is live. Testnet SN292 remains dry-run and does not pay
token emissions.

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

Attestation grants admission. Emissions come from verified delivery. Validators
never require SSH or remote root access to miner machines.

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
python -m pytest -q
```

The hardware-free suite exercises TDX policy verification, signed enrollment,
authenticated workers, deterministic audit work, validator-derived accounting,
complete score reports, and zero revocation. Attestation crypto is mocked behind
the real `verify()` interface; the real Intel TDX path runs on hardware (see
[`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md)).

## Documentation

- [`BUILD_STATUS.md`](BUILD_STATUS.md) - canonical mainnet and testnet launch evidence
- [`MINING.md`](MINING.md) - step-by-step miner onboarding
- [`docs/DESIGN.md`](docs/DESIGN.md) - protocol and scoring design
- [`docs/ASSURANCE.md`](docs/ASSURANCE.md) - four independent assurance claims
- [`docs/POLICY_REGISTRY.md`](docs/POLICY_REGISTRY.md) - signed measurement policy and lifecycle
- [`docs/RECEIPTS.md`](docs/RECEIPTS.md) - durable signed assurance receipts and offline verification
- [`docs/LIFECYCLE.md`](docs/LIFECYCLE.md) - continuous re-attestation, worker states, and retry behavior
- [`docs/WORKLOAD_ADMISSION.md`](docs/WORKLOAD_ADMISSION.md) - immutable signed workload admission contract
- [`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md) - Intel TDX attestation path
- [`HANDOFF.md`](HANDOFF.md) - commissioning and test handoff
- [`RUNTEST.md`](RUNTEST.md) - test commands

## License

MIT
