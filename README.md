<p align="center"><em>Rent a GPU like on Lium, trust it like a TEE enclave —<br/>and every idle cycle in between goes to solving, evaluating, and hosting in the open.</em></p>

# Cathedral

A Bittensor subnet (SN39) where **confidentiality is the admission rule** and
**verified work is the currency**. This repo is the confidential-compute
sidecar: it collects and verifies confidential attestation, freezes payable
confidential reports, and publishes them to the scorer-owned weight path.
Miners prove they run inside a genuine Trusted Execution Environment; that
attestation is the ticket to participate, not the paycheck.

This is a **greenfield build**. The trust topology of prior marketplace designs
(validator SSHes into miners as root) is deliberately inverted here — miners
*serve* attestation, validators never touch miner machines.

## For miners

The current promotion path keeps the existing scorer authoritative and adds a
demand-driven confidential-compute component under the global v3 contract:

1. When payable base and confidential populations both exist, the scorer
   allocates exactly 90% of aggregate mass to base and 10% to confidential
   compute across the union of their hotkeys. Compute-only hotkeys can earn.
2. With base scores but no payable confidential compute, the result is 100%
   base. With no base scores, composition fails closed to an empty vector.
3. If the thin validator is missing any hotkey from the signed vector, it drops
   all confidential mass and reconstructs a base-only vector from the mapped
   signed base components. Duplicate UID mappings are rejected.
4. The launch gate checks the aggregate contract through Bittensor u16
   quantization; with both populations present, the quantized confidential
   share must remain within tolerance of 10%.

Cathedral does not mine its own confidential lane. Cathedral-operated TDX
infrastructure exists to attest, verify, and publish the confidential snapshot;
it is not registered for emissions.

`cathedralai/cathedral` remains the sole Bittensor weight setter. This repo
intentionally carries **no direct Bittensor SDK dependency** and does not submit
weights on chain.

What you can do today:

1. **Run the testable core** — clone this repo, `pip install -e '.[dev]'`,
   `python -m pytest -q`. Understand the evidence flow in
   `cathedral/attest`, the verifier logic in `cathedral/verify`, and the SAT
   lane in `cathedral/lanes/sat.py`.
2. **Use the current scoring runtime** — TDX CPU is the active confidential
   scoring path in this repo. SNP cryptographic verification exists, but SNP
   runtime scoring is not enabled here today.
3. **Inspect the launch gate** — `scripts/cross_repo_launch_verify.py` proves
   the global v3 scorer integration against the external scorer checkout,
   including base-only fallback, duplicate-UID rejection, quantized aggregate
   attribution, and revocation when no payable verified compute remains.

Truthful working commands in this repo today:

- `cathedral --help`
- `cathedral runtime --help`
- `cathedral worker --help`
- `cathedral-validator --help`
- `cathedral-miner --help`
- `cathedral verify-quote --measurement abc --allowed-measurement abc --tcb 3 --min-tcb 1`
- `cathedral work submit --n-vars 3 --clauses '[[1,-2,3]]'`
- `cathedral work status`

The live claim in this branch is the attestation, runtime, worker, ledger,
poster, and cross-repo scoring path. The five-lane earning model remains future
design, not the current public earning surface of this sidecar.

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
policy. SNP quote parsing and cryptographic verification are implemented, but
runtime scoring still targets the TDX CPU path.

## License

MIT.
