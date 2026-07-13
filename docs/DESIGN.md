# Cathedral — Design

**A confidential compute subnet that directs attested hardware at verifiable work.**

Status: founding design for Cathedral's confidential-compute architecture. This
document is design and direction. For what is currently live, see
[`BUILD_STATUS.md`](../BUILD_STATUS.md): the proven path today is Intel TDX CPU
workers with deterministic validator-dispatched audit work, proven on testnet
SN292 in dry-run mode. The products, lanes, and hardware classes below beyond
that are planned direction, not current launch evidence.

---

## 1. Thesis

Cathedral's production target is Bittensor SN39. Its admission rule is hardware
attestation and its currency is verified work. Production chain submission is
not live; the current integration proof is the SN292 dry run described above.

Two sentences hold the whole design:

> **Confidentiality is our admission rule. Verified work is our currency.**

Every miner proves, cryptographically, that it runs inside a genuine Trusted Execution Environment (TEE) — a confidential CPU (AMD SEV-SNP, Intel TDX) or a confidential-compute GPU (NVIDIA H100/H200/B200 in CC or PPCIe mode). That attestation is the ticket to participate. It is **not** the paycheck. Miners earn through useful, verified work; idle attested hardware earns nothing.

Attestation alone pays nothing. Cathedral keeps attested machines busy: they are always visibly solving, evaluating, training, serving, and hosting.

### Confidentiality as the verification engine

Because Cathedral makes confidentiality the admission rule, **confidential compute is not only the privacy feature, it is the verification engine.** In every lane, the integrity of the work is inherited from the enclave measurement at near-zero marginal cost. That is what lets one thin validator run many lanes without becoming many separate codebases.

---

## 2. Products

Two products, two *different* guarantees. Keeping them distinct is a correctness requirement, not a marketing choice.

| | **Secure Sandbox** | **Core** |
|---|---|---|
| Guarantee | Integrity **+ confidentiality** | Integrity only |
| GPU worker | Subnet TEE hardware (CC-mode) | Open-market commodity GPU (untrusted) |
| Customer data on the worker | Encrypted, invisible to host | **Visible to the host** |
| Orchestrator | Attested TDX judge (Cathedral) | Attested TDX judge (Cathedral) |
| Supply | Scarce, premium, on-subnet | Elastic, cheap, off-subnet (rented on demand) |
| Sold for | Proprietary models, agent secrets, regulated data | Reproducible, checkable work (SAT, eval, open-model jobs) |

**Secure Sandbox** — the customer rents a confidential machine. SSH terminates *inside* a CVM; the host sees only encrypted memory and disk. The customer verifies a single attestation quote before the first keystroke and knows the machine's owner cannot see the workload.

**Core (Rented-Split)** — customer work is orchestrated by Cathedral's attested TDX judge, which delegates heavy compute to commodity GPUs rented on the open market. The judge holds the reference answers, fresh-seed challenges, and the customer's secrets; the rented GPU only ever sees a challenge harness and returns results the judge verifies. **The customer's trust terminates at the attested judge — not at the rented GPU.** Results are provably correct; they are **not** private from the GPU's owner.

### The trust boundary (say this on the security page)

- Customer trust terminates at Cathedral's **attested TDX judge**. Its measurement is published; its quote is verifiable by anyone.
- Everything beyond the judge (open-market GPUs) is inside the *verification* perimeter but outside the *trust* perimeter.
- Sandbox extends the trust perimeter all the way to the worker. Core does not. Data-sensitive customers are Sandbox customers. **Verified ≠ confidential.**

**Disclosure line (verbatim, in all Core documentation):**
> *Core jobs run on machines whose owners can observe the workload. Core guarantees the correctness of results, not the privacy of inputs. Data-sensitive workloads belong on Secure Sandbox.*

---

## 3. Two supply chains

**Subnet supply = confidential hardware only.** Admission requires a valid TEE
attestation. Intel TDX CPU is the proven path today. AMD SEV-SNP and NVIDIA CC
GPU evidence classes are planned platform extensions and do not earn in the
current runtime. Emissions bootstrap attested confidential hardware; delegated
commodity compute in the future Core product is not itself subnet supply. The
validator accepts only vendor-backed evidence that satisfies current nonce,
measurement, TCB, platform, and hotkey-binding policy.

**Commodity GPUs = procured, not mined.** For Core jobs, the judge rents commodity GPUs on demand from open markets, pushes the challenge harness, verifies, and tears down. These machines never touch the subnet, never earn emissions, never need admission logic. Zero demand → zero spend. Core's unit economics are ordinary business math (rent at market, sell verified execution at a markup), decoupled from tokenomics.

**Cathedral is its own anchor tenant.** The TDX judges are workloads inside TEEs. V1 runs them on Cathedral-owned boxes. Structurally, a judge is just an enclave workload — so later phases deploy judges *onto subnet CC-CPU miners* (safe because TDX hides the judge from the miner). Cathedral becomes its own first customer for CC-CPU capacity, and the operator's trust decentralizes measurably over time.

---

## 4. The lane model

The subnet is a **multi-lane verified work engine**, not a capacity pool.

```
Miner   = attested hardware + lane subscriptions (hardware-shaped)
Lane    = work queue + dispatcher + verifier + scorer
Weight  = Σ over lanes ( lane_emission_share × miner_verified_lane_score )
```

A miner attests once, then subscribes to the lanes its hardware shape qualifies for. The validator runs the lanes: dispatch work, verify per lane, compose scores through a steerable emission routing vector.

| Lane | Work unit | Verification | Hardware shape |
|---|---|---|---|
| **Inference** | tokens served on a pinned model | measurement pins weights-hash + runtime + config; validators probe latency / throughput / uptime | 8× CC-GPU |
| **Training** | training jobs / checkpoints | attested measured image ⇒ execution integrity by construction | multi CC-GPU |
| **RL** | rollout batches, learner steps | enclave-attested trajectories | CPU enclaves (envs) + CC-GPU (learners) |
| **Agent hosting** | agent-hours + liveness | attestation + liveness probes | small enclaves (CPU or GPU) |
| **SAT / benchmark** | certified solves, sealed eval runs | SAT assignment check (µs) / DRAT proof for UNSAT; sealed held-out test sets | big-core CPU enclaves |

**Verification is near-free in every lane, for one of two reasons:** SAT brings its own certificates; everything else inherits integrity from the enclave measurement. This is why one thin validator can run all five lanes.

### Lane interface (every lane implements this)

```
Lane:
  qualify(attestation)      -> bool           # hardware shape gate
  dispatch(miner, budget)   -> WorkItem        # customer job if present, else canonical work
  verify(WorkItem, result)  -> Certificate|None
  score(miner, [Certificate]) -> float         # feeds the weight-setter
```

`dispatch` prefers paying customer work at market price; when the customer queue is empty it backfills **canonical work** the subnet generates itself. Idle exists only where the routing vector allows; the remainder burns.

### Canonical (idle-default) work per lane

- **SAT** — standing bounty queue: SAT-Competition suites, open combinatorial problems (Ramsey-type bounds, packing, EDA verification instances). Difficulty-weighted, paid per certified solve. Manufactures public headlines ("SN39 closed instance X") and rewards better solver strategy, not just more cores.
- **Benchmark** — continuous attested evaluation of open models; sold as neutral third-party evaluation to *other subnets* (sealed test sets nobody can juice, including us). Makes Cathedral load-bearing for the ecosystem.
- **Inference** — serve open models on public endpoints. Differentiator: **provably unquantized** — the attestation proves the exact weights and runtime, defeating the silent-quantization problem no other provider can address.
- **RL** — open RL research rollouts / standing agent competitions with enclave-attested trajectories (no fabricated rollouts, no reward-report hacking).
- **Agent hosting** — dogfood: the first agents are Cathedral's own (judges, market-renter agents, ops agents). "Sovereign agents" whose keys provably cannot be extracted by anyone, host included.

---

## 5. Emissions

Two layers:

1. **Verified work.** Validator-derived credit for useful jobs and unpredictable audit work. Attestation only admits the worker.
2. **Unallocated mass.** Work that did not happen pays nobody. A failed, missing, stale, or unverifiable result receives an explicit zero.

### Dedicated compute stream

Cathedral owns SN39's full score surface. It does not compose with another
scorer or reserve a fixed secondary allocation.

- **Complete epochs:** Cathedral challenges miners, verifies evidence and
  delivery, derives work units, and freezes a complete compute epoch.
- **Complete signed stream:** every epoch contains the latest state for every
  observed hotkey, including explicit zeros that revoke stale credit.
- **Validator path:** Cathedral publishes the signed compute vector to the
  validator feed. In production, SN39 validators will verify it, map registered
  hotkeys to current UIDs, reject duplicate mappings, and submit weights to
  Bittensor. The current SN292 proof stops before chain submission.
- **Fail closed:** an invalid signature, incomplete identity map, stale report,
  failed attestation, or failed job cannot preserve old weight.
- **Open entry:** admission follows published hardware and measurement policy,
  not an operator allowlist or privileged machine access.

This repository owns attestation, work verification, accounting, and the signed
compute stream. It does not need a second Bittensor neuron stack.

### Lane routing

Future multi-lane routing will be an explicit, governance-visible per-epoch
table whose shares sum to the subnet's complete score vector. The current
runtime has one scored path: deterministic SAT audit work on admitted TDX CPU
workers. New lanes must ship with their own qualification, dispatch,
verification, scoring, and zero-revocation acceptance tests before receiving
any routing share.

### Credit validation: preventing inflation and replay

Miners cannot choose their own credit. Every work unit's difficulty and credit is **validator-derived** at verification time from the instance itself, never from the miner's claim.

**Challenge identity (challenge_id).** Every dispatched work item carries a deterministic, immutable hash of its (instance, seed) tuple. This hash is computed by the validator before dispatch and cannot be forged by a miner. Encoding the seed in the hash ties each challenge to its canonical generation, preventing a replay of the same challenge across epochs (one physical challenge = one possible credit line).

**Credit immutability.** In SAT, the validator computes work units from the instance's clause count, never from `result.work_units`. If a miner claims 1e300, NaN, −5, or Infinity, the validator-derived value wins; the miner's claim is ignored. Defense-in-depth at the score level rejects any miner-supplied or manually-forged certificate with non-finite or negative work units, even if it leaks past verification().

**Invariants:**
- Every dispatched challenge has a unique challenge_id (via monotonic seed counter).
- Only validator-derived work units affect scoring; miner claims are irrelevant.
- The validator's routing application ensures finite, nonnegative weights that sum to ~1.0 (+ burn).

---

## 6. Attestation core (the security spine)

**Miner-side attestor** collects evidence and binds the challenge:
- SEV-SNP: report via `/dev/sev-guest`
- TDX: guest calls `TDG.MR.REPORT` (TDCALL) → TDREPORT → host Quote Generation Service → DCAP quote
- GPU: NVIDIA attestation via NVML / nvtrust
- **Binding:** `REPORT_DATA = sha512(nonce ‖ miner_hotkey ‖ ssh_host_key?)`. The nonce gives freshness; the hotkey binds the evidence to the registered identity (defeats evidence-relay — one machine fronting for many UIDs); the SSH host key (Sandbox) binds the rental channel into the quote.

**Validator-side verifier** does policy; vendors do the crypto:
- AMD KDS cert chains, Intel DCAP / Trust Authority, NVIDIA NRAS/nvtrust
- **Composite attestation** (Sandbox on CC-GPU): Intel Trust Authority binds the CPU TDX quote and the GPU CC evidence into a single JWT
- Policy engine: allowed measurements, minimum TCB, allowed firmware/driver versions
- **Sybil defense is free:** SNP `CHIP_ID`, TDX platform ID, and certified GPU UUIDs live in the evidence — one physical machine backs exactly one UID; dedup is a dictionary, not a subsystem.

The guest instruction is `TDG.MR.REPORT`, not `SEAMREPORT`. An SM-latency GPU
probe is a fingerprint or scoring heuristic, never attestation: it has no
vendor key or cryptographic root. The confidential coordinator, including its
runtime and lease state, must remain inside the measured trust boundary.

---

## 7. Rental delivery (Sandbox)

The rental unit is a **CVM, not a container**. The move that makes SSH-into-a-CVM trustworthy (~30 lines):

1. Host-agent launches a CVM from Cathedral's signed, measured image; renter GPU passed through in CC mode.
2. Guest-agent generates the SSH host key at boot, requests a quote with `sha512(ssh_host_key ‖ renter_pubkey ‖ nonce)` in `REPORT_DATA`.
3. Renter CLI verifies the quote (measurement matches published image hash, TCB current, nonce fresh) and pins the host key from it.
4. `ssh` connects. Matching fingerprint ⇒ the session terminates inside genuine confidential hardware running exactly Cathedral's image. Host cannot MITM, inspect, or fake it.

Renter has root inside the CVM: install anything, run Docker, use the GPU. Feels like an ordinary cloud GPU pod; invisible to its landlord.

**Data gravity:** bake large model weights into pre-staged, measured base images; push only the lightweight harness, tolerance bounds, and fresh-seed challenge over the wire. Preserves the 1–2 minute cold-start target.

**No Kubernetes in the control plane.** CVM = pod; the "orchestrator" is a ~200-line allocator matching pod requests to attested capacity. A renter who wants K8s runs `k3s` *inside their own CVM* — orchestration is their workload, not our platform. Confidential-K8s (Kata / CoCo / peer-pods) is a deferred, additive later phase.

---

## 8. On-chain (thin cut)

Bittensor weights **are** the launch-day slashing mechanism: invalid quote → weight 0 → no emission. No contract required to start.

When off-subnet customers need trustless settlement, add one **Verification
contract** on Bittensor's EVM. It ingests cryptographically verified hardware
receipts, gates payment release, and slashes collateral on invalid evidence.

**Explicitly cut** (violate "super thin"): the multi-contract "Trias Politica" DAG governance stack (on-chain workflow is expensive state the TDX judge already handles off-chain — the chain needs *receipts*, not *workflow*); the judicial-DAO Guardian circuit breaker (an owner-key pause is honest and adequate at this stage); the ZK data bridge (a separate product, not this roadmap).

---

## 9. Implementation boundary

The attestor, verifier, policy engine, CVM stack, and lane engine are Cathedral
components. Miners serve attestation and work endpoints; validators never need
root access to miner machines. The production target remains SN39, while the
current integration proof runs on testnet SN292.

**Language:** Python (mature `bittensor` SDK; NVIDIA nvtrust, AMD/Intel tooling all have Python paths). Attestor may become a small static Rust binary later if distribution demands.

**Thinness rules:** one service per role; systemd, not K8s; Postgres, not a distributed store; immutable measured guest images (replace, never patch); the attestation probe doubles as the billing heartbeat (no separate monitoring stack).

---

## 10. Build phases

Each phase ships alone; nothing blocks on the phase after it.

- **Phase 0 — now (~1–2 wk).** Land the rename. `TeeEvidence` proto (SNP | TDX | GPU, nonce+hotkey binding). CC census probe (`/dev/sev-guest`, TDX support, `nvidia-smi conf-compute -q`) to measure launch supply. *Launch path: TDX CPU first on a live Intel TDX CVM; SNP verification exists, but SNP runtime scoring is the next CPU platform port.*
- **Phase 1 — attestation core (~4–6 wk).** `cathedral-attestor` + `cathedral-verifier` (KDS / DCAP / NRAS + policy engine). Admission gates on attestation and earnings gate on verified work. SAT is the first audit lane because it is cheap to verify and has broad CPU supply.
- **Phase 2 — lanes (~4–6 wk).** Lane engine + the five lanes' dispatch/verify/score. Routing vector wired to the weight-setter. Canonical work queues live. Demand-preempt + burn.
- **Phase 3 — Sandbox rentals (~6–10 wk).** Host-agent (cloud-hypervisor/QEMU + TDX/SNP + VFIO passthrough), measured guest image + build pipeline, attested SSH (host-key binding), control-plane API + CLI + MCP. CC-CPU pods first, CC-GPU second.
- **Phase 4 — Core (rented-split) (~2–3 wk).** `suppliers/` module (commodity GPU rental backends), challenge harness + tolerance bounds, judge deployment. Opens the commodity-GPU floodgates for SAT / eval / open-model jobs.
- **Phase 5 — settlement.** EVM Verification contract when off-subnet customers need trustless payment. Composite attestation for CC-GPU Sandbox. Confidential-K8s if demanded.

**Sizing:** attestation-gated subnet core ≈ 1–2k LOC; full rentable platform ≈ 5–7k LOC; +2–3k for Core's verification harness and the EVM contract. Real cost is not lines — it is the guest-image build pipeline and the firmware/driver matrix (BIOS access, HGX firmware versions, per-platform Ubuntu). Dev hardware is the critical path: a TDX CPU box now, then SNP and a CC-capable H100/H200 for later platform coverage.

---

## 11. Use cases (the five lanes, restated as demand)

1. **Training** — model training on rented confidential GPUs.
2. **Reinforcement learning** — env fleets (CPU enclaves) + learners (CC-GPU), long-running, attested trajectories.
3. **Agent hosting** — long-lived agents holding secrets, network-exposed; keys provably unextractable by anyone including the host.
4. **SAT solving & benchmarking** — combinatorial solving with self-certifying results; sealed, attested evaluation sold as a neutral service.
5. **Inference** — open models on 8× CC-GPU, public endpoints, provably unquantized.

---

## 12. One-line positioning

**Confidential hardware, verified work, and every cycle in between pointed at solving, evaluating, and hosting in the open.**

Confidentiality is the admission rule. Verified work is the currency. The lanes are where the compute is pointed.
