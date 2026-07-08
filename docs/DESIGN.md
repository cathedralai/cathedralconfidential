# Cathedral — Design

**A confidential compute subnet that directs attested hardware at verifiable work.**

Status: founding design. Supersedes the "verified GPU rental marketplace" thesis inherited from the Basilica fork.

---

## 1. Thesis

Cathedral is a Bittensor subnet (SN39) where the admission rule is hardware attestation and the currency is verified work.

Two sentences hold the whole design:

> **Confidentiality is our admission rule. Verified work is our currency.**

Every miner proves, cryptographically, that it runs inside a genuine Trusted Execution Environment (TEE) — a confidential CPU (AMD SEV-SNP, Intel TDX) or a confidential-compute GPU (NVIDIA H100/H200/B200 in CC or PPCIe mode). That attestation is the ticket to participate. It is **not** the paycheck. Miners earn by completing verified work in one of five lanes. Idle attested hardware earns a thin floor and nothing more; unearned emission burns.

This inverts the usual confidential-compute subnet, which sells trust and then waits. Cathedral is never idle: attested machines are always visibly solving, evaluating, training, serving, and hosting.

### Why this is not a boring CC subnet

Most compute subnets spend their entire innovation budget verifying work done on untrusted hardware (output sampling, deterministic replay, sumcheck proofs, benchmark gauntlets). Because Cathedral makes confidentiality the admission rule, **CC is not only the privacy feature — it is the verification engine.** In every lane, the integrity of the work is inherited from the enclave measurement at near-zero marginal cost. That is what lets one thin validator run five lanes without becoming five subnets' worth of code.

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

**Core (Rented-Split)** — customer work is orchestrated by Cathedral's attested TDX judge, which delegates heavy compute to commodity GPUs rented on the open market (Lium, Vast, RunPod). The judge holds the reference answers, fresh-seed challenges, and the customer's secrets; the rented GPU only ever sees a challenge harness and returns results the judge verifies. **The customer's trust terminates at the attested judge — not at the rented GPU.** Results are provably correct; they are **not** private from the GPU's owner.

### The trust boundary (say this on the security page)

- Customer trust terminates at Cathedral's **attested TDX judge**. Its measurement is published; its quote is verifiable by anyone.
- Everything beyond the judge (open-market GPUs) is inside the *verification* perimeter but outside the *trust* perimeter.
- Sandbox extends the trust perimeter all the way to the worker. Core does not. Data-sensitive customers are Sandbox customers. **Verified ≠ confidential.**

**Disclosure line (verbatim, in all Core documentation):**
> *Core jobs run on machines whose owners can observe the workload. Core guarantees the correctness of results, not the privacy of inputs. Data-sensitive workloads belong on Secure Sandbox.*

---

## 3. Two supply chains

**Subnet supply = confidential hardware only.** Admission requires a valid TEE attestation. Accepted evidence classes: AMD SEV-SNP (EPYC 7003 "Milan" and newer), Intel TDX (5th-gen Xeon Scalable and newer), and NVIDIA CC GPUs (H100/H200 Hopper CC, B200/B300 Blackwell) attested compositely with their host CPU TEE. No commodity GPUs, no benchmark tiers, no waivers. Emissions exist to bootstrap the one thing that is scarce and hard to find: attested confidential hardware. This single admission rule keeps the validator simple and eliminates the spoofing/sybil surface — a DCAP quote cannot be faked by a clever miner.

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

Three layers:

1. **Attestation floor (~10–15%).** Valid TEE evidence + liveness. Just enough that keeping hardware attested and TCB-current is worthwhile.
2. **Work layer (majority).** Weighted by completed, verified work units, composed through the routing vector.
3. **Burn.** Work that did not happen pays nobody. (`burn_uid` / `forced_burn_percentage` already exist in the inherited validator config.)

### The routing vector = "directing compute to the primitives," made mechanical

Emission split across lanes is an explicit, governance-visible, per-epoch table:

```
routing = { inference: 0.30, training: 0.20, rl: 0.15, agents: 0.10, sat: 0.25 }
```

Want more CPU enclaves this quarter? Raise the SAT lane. Need CC-GPUs for an eval customer? Shift weight to inference/benchmark. The subnet does not merely *admit* confidential hardware — it *steers* it, and everyone can see where it is pointed. Demand preempts canonical work in any lane at market price.

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

**Corrections carried from prior drafts:** the guest instruction is `TDG.MR.REPORT`, not `SEAMREPORT`. The SM-latency GPU probe is a *fingerprint / scoring heuristic* for Core's commodity tier, never called "attestation" (no vendor key, no cryptographic root). Any external broker (e.g. a Cloudflare Worker) in the confidential path is a trust violation — the entire coordinator (runtime + Postgres + lease state) runs **inside** the TD.

---

## 7. Rental delivery (Sandbox)

The rental unit is a **CVM, not a container**. The move that makes SSH-into-a-CVM trustworthy (~30 lines):

1. Host-agent launches a CVM from Cathedral's signed, measured image; renter GPU passed through in CC mode.
2. Guest-agent generates the SSH host key at boot, requests a quote with `sha512(ssh_host_key ‖ renter_pubkey ‖ nonce)` in `REPORT_DATA`.
3. Renter CLI verifies the quote (measurement matches published image hash, TCB current, nonce fresh) and pins the host key from it.
4. `ssh` connects. Matching fingerprint ⇒ the session terminates inside genuine confidential hardware running exactly Cathedral's image. Host cannot MITM, inspect, or fake it.

Renter has root inside the CVM: install anything, run Docker, use the GPU. Feels like a Lium pod; invisible to its landlord.

**Data gravity:** bake large model weights into pre-staged, measured base images; push only the lightweight harness, tolerance bounds, and fresh-seed challenge over the wire. Preserves the 1–2 minute cold-start target.

**No Kubernetes in the control plane.** CVM = pod; the "orchestrator" is a ~200-line allocator matching pod requests to attested capacity. A renter who wants K8s runs `k3s` *inside their own CVM* — orchestration is their workload, not our platform. Confidential-K8s (Kata / CoCo / peer-pods) is a deferred, additive later phase.

---

## 8. On-chain (thin cut)

Bittensor weights **are** the launch-day slashing mechanism: invalid quote → weight 0 → no emission. No contract required to start.

When off-subnet customers need trustless settlement, add exactly one **Verification contract** on Bittensor's EVM: ingests DCAP quotes via Automata's `automata-dcap-attestation` (SNARK-compressed path, ~300k gas), gates payment release, slashes collateral on invalid evidence. This is Nodexo's `CollateralManager` pattern with hardware receipts.

**Explicitly cut** (violate "super thin"): the multi-contract "Trias Politica" DAG governance stack (on-chain workflow is expensive state the TDX judge already handles off-chain — the chain needs *receipts*, not *workflow*); the judicial-DAO Guardian circuit breaker (an owner-key pause is honest and adequate at this stage); the ZK data bridge (a separate product, not this roadmap).

---

## 9. What we build vs. what we keep

**Greenfield the core.** The hard parts (attestor, verifier, policy engine, CVM stack, lane engine) do not exist in the fork and must be written new regardless. The fork's model — validator SSHes into miners as root to run benchmark binaries — is the wrong trust topology; Cathedral inverts it (miners *serve* attestation; validators never touch miner machines).

**Keep from the fork (as reference, not code):** the `TeeEvidence` / `GpuAttestation` proto shapes, the category/pricing vocabulary, the ops lessons in commit history, and — critically — **SN39 itself**: the subnet slot, registrations, and community carry over regardless of which codebase the neurons run.

**Language:** Python (mature `bittensor` SDK; NVIDIA nvtrust, AMD/Intel tooling all have Python paths). Attestor may become a small static Rust binary later if distribution demands.

**Thinness rules:** one service per role; systemd, not K8s; Postgres, not a distributed store; immutable measured guest images (replace, never patch); the attestation probe doubles as the billing heartbeat (no separate monitoring stack).

---

## 10. Build phases

Each phase ships alone; nothing blocks on the phase after it.

- **Phase 0 — now (~1–2 wk).** Land the rename. `TeeEvidence` proto (SNP | TDX | GPU, nonce+hotkey binding). CC census probe (`/dev/sev-guest`, TDX support, `nvidia-smi conf-compute -q`) to measure launch supply. *Blocker: one SNP-capable EPYC bare-metal box.*
- **Phase 1 — attestation core (~4–6 wk).** `cathedral-attestor` + `cathedral-verifier` (KDS / DCAP / NRAS + policy engine). Admission and emissions gate on attestation. Cathedral is now an attestation-gated subnet with the attestation floor + a first lane (SAT — cheapest verification, biggest CPU supply).
- **Phase 2 — lanes (~4–6 wk).** Lane engine + the five lanes' dispatch/verify/score. Routing vector wired to the weight-setter. Canonical work queues live. Demand-preempt + burn.
- **Phase 3 — Sandbox rentals (~6–10 wk).** Host-agent (cloud-hypervisor/QEMU + TDX/SNP + VFIO passthrough), measured guest image + build pipeline, attested SSH (host-key binding), control-plane API + CLI + MCP. CC-CPU pods first, CC-GPU second.
- **Phase 4 — Core (rented-split) (~2–3 wk).** `suppliers/` module (Lium/Vast/RunPod backends), challenge harness + tolerance bounds, judge deployment. Opens the commodity-GPU floodgates for SAT / eval / open-model jobs.
- **Phase 5 — settlement.** EVM Verification contract when off-subnet customers need trustless payment. Composite attestation for CC-GPU Sandbox. Confidential-K8s if demanded.

**Sizing:** attestation-gated subnet core ≈ 1–2k LOC; full rentable platform ≈ 5–7k LOC; +2–3k for Core's verification harness and the EVM contract. Real cost is not lines — it is the guest-image build pipeline and the firmware/driver matrix (BIOS access, HGX firmware versions, per-platform Ubuntu). Dev hardware is the critical path: an SNP EPYC box now, a TDX host and a CC-capable H100/H200 for Phases 3–4.

---

## 11. Use cases (the five lanes, restated as demand)

1. **Training** — model training on rented confidential GPUs.
2. **Reinforcement learning** — env fleets (CPU enclaves) + learners (CC-GPU), long-running, attested trajectories.
3. **Agent hosting** — long-lived agents holding secrets, network-exposed; keys provably unextractable by anyone including the host.
4. **SAT solving & benchmarking** — combinatorial solving with self-certifying results; sealed, attested evaluation sold as a neutral service.
5. **Inference** — open models on 8× CC-GPU, public endpoints, provably unquantized.

---

## 12. One-line positioning

**Rent a GPU like on Lium, trust it like a Targon enclave — and every idle cycle in between goes to solving, evaluating, and hosting in the open.**

Confidentiality is the admission rule. Verified work is the currency. The five lanes are where the compute is pointed.
