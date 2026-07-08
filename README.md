<p align="center"><em>Rent a GPU like on Lium, trust it like a TEE enclave —<br/>and every idle cycle in between goes to solving, evaluating, and hosting in the open.</em></p>

# Cathedral

A Bittensor subnet (SN39) where **confidentiality is the admission rule** and
**verified work is the currency**. Miners prove they run inside a genuine
Trusted Execution Environment (CPU TEE or CC-mode GPU); that attestation is the
ticket to participate, not the paycheck. Miners earn by completing verified work
in five lanes — inference, training, RL, agent hosting, and SAT/benchmark — and
idle attested hardware earns only a thin floor. Unearned emission burns.

This is a **greenfield build** with a deliberately inverted trust topology:
miners *serve* attestation, validators never touch miner machines.

## Read first

- [`HANDOFF.md`](HANDOFF.md) — **start here to run or commission.** Run the
  testable core in 5 minutes. The original handoff is SNP-first; launch work is
  now TDX CPU first because live Cathedral supply is already on a GCP TDX CVM.
- [`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md) — **current launch path.** Use the
  live TDX CPU box to prove real attestation, then port the same interface to
  SNP after launch.
- [`docs/DESIGN.md`](docs/DESIGN.md) — the founding design. Products, supply
  chains, the lane model, emissions, attestation core, rental delivery, the
  thin on-chain cut, and the phased build plan.
- [`RUNTEST.md`](RUNTEST.md) — per-command test breakdown.

## Two products

| | Secure Sandbox | Core |
|---|---|---|
| Guarantee | integrity **+ confidentiality** | integrity only |
| Worker | subnet TEE hardware (CC-mode) | open-market commodity GPU (untrusted) |
| Sold for | proprietary models, agent secrets, regulated data | reproducible, checkable work |

> Core jobs run on machines whose owners can observe the workload. Core
> guarantees the correctness of results, not the privacy of inputs.
> Data-sensitive workloads belong on Secure Sandbox.

## Layout

```
proto/evidence.proto     TEE attestation evidence schema (SNP | TDX | GPU)
cathedral/
  common.py              config, tiers, nonces, evidence types
  census.py              Phase 0 — CC capability probe (real, hardware-free to run)
  attest/                miner-side evidence collectors (SNP / TDX / GPU)
  verify/                validator-side verifiers + measurement policy
  lanes/                 the five-lane work engine (dispatch / verify / score)
  neuron/                miner.py, validator.py
docs/DESIGN.md           founding design
```

## Status

Phase 0 / Phase 1 bridge. The hardware-free core is green, and the launch path
is TDX CPU first. The TDX collector uses Linux configfs-tsm; validator-side
verification delegates DCAP / Trust Authority crypto to an external verifier and
then enforces Cathedral's nonce, hotkey, measurement, TCB, and platform-id
policy.

## License

MIT.
