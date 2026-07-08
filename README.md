<p align="center"><em>Rent a GPU like on Lium, trust it like a TEE enclave —<br/>and every idle cycle in between goes to solving, evaluating, and hosting in the open.</em></p>

# Cathedral

A Bittensor subnet (SN39) where **confidentiality is the admission rule** and
**verified work is the currency**. Miners prove they run inside a genuine
Trusted Execution Environment (CPU TEE or CC-mode GPU); that attestation is the
ticket to participate, not the paycheck. Miners earn by completing verified work
in five lanes — inference, training, RL, agent hosting, and SAT/benchmark — and
idle attested hardware earns only a thin floor. Unearned emission burns.

This is a **greenfield build**. The prior benchmark-verified marketplace
(forked from Basilica) lives at `bigailabs/cathedral-archived` as reference; its
trust topology (validator SSHes into miners as root) is deliberately inverted
here — miners *serve* attestation, validators never touch miner machines.

## Read first

- [`HANDOFF.md`](HANDOFF.md) — **start here to run or commission.** Run the
  testable core in 5 minutes, or commission a real SEV-SNP box and build the
  first hardware attestation test (Phase 1, the critical path).
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

Phase 0. See `docs/DESIGN.md §10` for the phase plan. The census probe and the
evidence schema are the first hardware-free deliverables; the attestor and
verifier need an SNP-capable EPYC box to develop against (the critical path).

## License

MIT. Forked-from lineage: `bigailabs/cathedral-archived` (itself forked from
one-covenant/basilica).
