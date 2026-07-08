<p align="center"><em>Rent a GPU like on Lium, trust it like a TEE enclave —<br/>and every idle cycle in between goes to solving, evaluating, and hosting in the open.</em></p>

# Cathedral

A Bittensor subnet (SN39) where **confidentiality is the admission rule** and
**verified work is the currency**. Miners prove they run inside a genuine
Trusted Execution Environment (CPU TEE or CC-mode GPU); that attestation is the
ticket to participate, not the paycheck. Miners earn by completing verified work
in five lanes — inference, training, RL, agent hosting, and SAT/benchmark — and
idle attested hardware earns only a thin floor. Unearned emission burns.

This is a **greenfield build**. The trust topology of prior marketplace designs
(validator SSHes into miners as root) is deliberately inverted here — miners
*serve* attestation, validators never touch miner machines.

## For miners

Target economy: **50/50 between SAT and attested confidential compute**.
The confidential share phases in on a published, adoption-gated schedule:

| Attested miners in the lane | Confidential share of emissions |
|---|---|
| Shadow phase | 0% (scores published, proof visible) |
| Lane opens, fewer than 5 | 10% |
| 5 to 20 | 25% |
| 20+ | **50% — target economy** |

First movers split the largest per-miner pool the lane will ever pay.
Two commitments: SAT miners are never diluted by an empty lane (the
confidential share only exists when real attested miners are earning it),
and Cathedral does not mine its own lane — our confidential hardware runs
verification infrastructure only and is never registered for emissions.
The existing SAT scorer stays authoritative throughout — this lane is
additive.

What you can do today:

1. **Run the testable core** — clone this repo, `pip install -e '.[dev]'`,
   `python -m pytest -q` (40 tests, no special hardware). Understand the
   evidence flow in `cathedral/attest` and the SAT lane in
   `cathedral/lanes/sat.py`.
2. **Prep confidential hardware** — Intel TDX or AMD SEV-SNP capable CPU
   (CC-mode GPU support follows). Attestation is the admission ticket:
   no genuine TEE evidence, no lane access.
3. **Watch this repo** — intake opens after the shadow phase proves
   attestation, UID mapping, and verified-work behavior on live data.

No change to your existing SN39 SAT mining is needed for any of this.

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

MIT.
