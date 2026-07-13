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

The current promotion path keeps the existing scorer authoritative and adds a
separate confidential-compute component that is **capped at 10%**.

Three commitments govern that component:

1. It is **demand-driven**: Cathedral only attributes confidential weight from
   payable, verified confidential-compute reports.
2. It is **zero when no payable verified compute exists**: an empty or
   fully-revoked confidential snapshot contributes nothing, so SAT miners are
   not diluted by an empty lane.
3. It is **bounded end to end**: the launch gate checks the scorer-side blend,
   survivor/UID merges, and Bittensor u16 quantization so realized confidential
   attribution never exceeds 10%.

Cathedral does not mine its own confidential lane. Cathedral-operated TDX
infrastructure exists to attest, verify, and publish the confidential snapshot;
it is not registered for emissions.

What you can do today:

1. **Run the testable core** — clone this repo, `pip install -e '.[dev]'`,
   `python -m pytest -q`. Understand the evidence flow in
   `cathedral/attest`, the verifier logic in `cathedral/verify`, and the SAT
   lane in `cathedral/lanes/sat.py`.
2. **Prep confidential hardware** — Intel TDX or AMD SEV-SNP capable CPU
   (CC-mode GPU support follows). Attestation is the admission ticket:
   no genuine TEE evidence, no confidential-compute credit.
3. **Inspect the launch gate** — `scripts/cross_repo_launch_verify.py` proves
   the capped 10% scorer integration against the external scorer checkout and
   revokes the confidential overlay back to zero when no payable verified
   compute remains.

This repo does not yet claim launch-ready neuron entrypoints or operator CLIs.
The live claim in this branch is the attestation, runtime, ledger, poster, and
cross-repo scoring path.

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
