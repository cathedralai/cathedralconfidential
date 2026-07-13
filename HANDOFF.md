# Cathedral — Commissioning & Test Handoff

Everything you need to (A) run the hardware-free testable core right now, and
(B) commission a real Trusted Execution Environment box and build the first
*real* attestation test on it. Read `docs/DESIGN.md` first for the why; this
file is the how.

> **Launch update.** This handoff was originally written SNP-first. For launch,
> Cathedral is going TDX CPU first because a live GCP TDX CVM is already running
> the Cathedral publisher. Use `docs/TDX_LAUNCH.md` for the current real
> attestation path; keep the SNP sections below as the next CPU platform port.
> SNP quote parsing and cryptographic verification exist in-repo, but runtime
> scoring remains TDX CPU first.

> **The one-line status.** The subnet mechanics + the SAT lane are real and
> tested. The attestation verdict is currently **mocked** in the validator epoch
> and real TDX collection / external-verifier adapter code is now scaffolded
> behind the same `verify()` interface. Commissioning a box is about replacing
> that mock with a genuine vendor-verified quote — that is Phase 1, and it is
> the critical path. Nothing downstream of an `Attested` verdict changes.

---

## 0. Two tracks at a glance

| | Track A — Testable core | Track B — Real attestation |
|---|---|---|
| Hardware | any Linux box (or a laptop) | SEV-SNP CPU (cloud CVM or bare-metal EPYC) |
| Proves | SAT lane, economics, sybil dedup, epoch mechanics | a real hardware quote round-trips and verifies |
| Time | ~5 minutes | ~1–3 hours (cloud) / ~half a day (bare metal) |
| Cost | free | ~$0.50–$2/hr (cloud CVM) |
| Status | ✅ done, green | 🔨 Phase 1 — you build it on the box |

Do Track A first (confidence the core works), then Track B (bring up hardware
and close the mock gap). Start Track B on a **cloud confidential VM** — it is
the fastest way to a real `/dev/sev-guest`; do bare metal later for production.

---

## 1. Track A — run the testable core (any machine, no hardware)

Requires Python 3.11+ and git. Nothing else.

```bash
# get the code
git clone https://github.com/cathedralai/cathedralconfidential.git cathedral
cd cathedral

python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

python -m pytest -q             # expect the current full suite count from RUNTEST.md
python scripts/demo_sat.py      # expect: ... PASS
python -m cathedral.census      # prints CC capability of THIS box (exit 1 if none)
cathedral-validator --help      # compatibility wrapper -> cathedral runtime ...
cathedral-miner --help          # compatibility wrapper -> cathedral worker ...
```

**What the hardware-free pass is telling you:** the nonce/REPORT_DATA binding,
the SAT solve→verify→reject-forgery→reject-contradiction loop,
emission-conserving economics (floor + routing + burn = 1.0), the work queue /
tier-gated allocator, mock attestation with `chip_id` sybil dedup, TDX verifier
adapter policy checks, and a full validator epoch (admit → run SAT → weights sum
to ~1.0). See `RUNTEST.md` for the per-command breakdown.

If Track A is green, the subnet's logic is sound. Everything below is about
swapping the *mock* attestation for the *real* thing.

---

## 2. Track B — real CPU attestation

Launch path is TDX CPU first; see `docs/TDX_LAUNCH.md`. The SEV-SNP notes below
are preserved because SNP is the next CPU platform port and uses the same
collector / verifier boundary.

### 2.1 Why the original draft chose SEV-SNP first

Per `docs/DESIGN.md §3`, SEV-SNP is the widest confidential-compute supply
(every AMD EPYC since 7003 "Milan", 2021) and the simplest quote path. TDX and
GPU-CC come after; the module boundaries are identical, so getting SNP working
end-to-end de-risks all three.

### 2.2 Fastest path — a cloud confidential VM (recommended for the first test)

You do **not** need to touch a BIOS to get a real SNP quote. Any of these give
you a guest with a working `/dev/sev-guest`:

- **Azure** — `DCasv5` / `DCadsv5` / `ECasv5` families (AMD SEV-SNP confidential
  VMs). Pick Ubuntu 24.04. These boot as SNP guests out of the box.
- **GCP** — Confidential VM with **SEV-SNP** (`n2d` or `c3d` machine types,
  confidential-compute type = `SEV_SNP`). Ubuntu 24.04.
- **Bare-metal providers** — Latitude.sh, Vultr bare metal, OVH, or any EPYC
  Genoa box where you control the BIOS (see §2.3).

Provision one, SSH in, then confirm the guest device exists:

```bash
ls -l /dev/sev-guest            # must exist inside an SNP guest
dmesg | grep -i -E "sev|snp"    # should show SEV-SNP guest active
```

If `/dev/sev-guest` is missing, the VM is not running as an SNP guest — recreate
it with the confidential-VM option explicitly enabled (it is often off by
default).

### 2.3 Bare-metal EPYC (production path, do later)

On an EPYC 7003 (Milan) / 9004 (Genoa) / 9005 (Turin) host you must, in BIOS:

- **CPU / SMEE**: enable *Secure Memory Encryption* (SME).
- **SEV / SEV-ES / SEV-SNP**: enable all three. Set **SNP Memory Coverage** /
  RMP to enabled.
- **Minimum SEV-SNP ASIDs**: set > 0 (e.g. 100+).
- **IOMMU**: enabled.

Host software (exact versions depend on your distro — verify against your
kernel):

- A host kernel with **SEV-SNP host** support (mainline Linux ≥ 6.11, or your
  distro's confidential-computing kernel). Ubuntu 24.04 HWE / 25.04 are the
  path-of-least-resistance.
- QEMU ≥ 9.x and an OVMF/EDK2 build with SNP support to launch guests.
- Launch an SNP guest, SSH into the **guest**, and confirm `/dev/sev-guest` as
  in §2.2.

> Bare metal is a real yak-shave (firmware + host kernel + guest launch). Prove
> the whole pipeline on a cloud CVM first; only bring up bare metal when you
> need custom hardware or margins.

---

## 3. The attestation tooling (`snpguest`)

The standard open-source CLI for SNP guest attestation is **`snpguest`** (from
the VirTEE project, Rust). It requests a report from `/dev/sev-guest`, fetches
the AMD cert chain from the **Key Distribution Service (KDS)**, and verifies.

```bash
# install rust if needed, then:
cargo install snpguest        # OR build from github.com/virtee/snpguest

# 1. request a report, binding 64 bytes of REPORT_DATA (this is the whole game)
#    put your challenge bytes in request-data.bin (see §4 for the exact bytes)
snpguest report attestation-report.bin request-data.bin

# 2. fetch the versioned cert chain (VCEK + ASK + ARK) from AMD KDS
snpguest fetch vcek DER ./certs attestation-report.bin
snpguest fetch ca   DER ./certs attestation-report.bin

# 3. verify: signature chain + that the report is genuine AMD-signed
snpguest verify certs ./certs
snpguest verify attestation attestation-report.bin ./certs

# 4. read the fields you care about (measurement, chip_id, tcb, report_data)
snpguest display report attestation-report.bin
```

The fields that map to `cathedral.common.Attested`:

| Cathedral field | SNP report field | Notes |
|---|---|---|
| `measurement` | `MEASUREMENT` | the launch digest — matched against `Policy.allowed_measurements` |
| `chip_id` | `CHIP_ID` | unique per physical CPU — **free sybil dedup** (one machine → one UID) |
| `tcb` | `CURRENT_TCB` / reported TCB | matched against `Policy.min_tcb` |
| (binding check) | `REPORT_DATA` | must equal `report_data(nonce, hotkey)` — see §4 |

TDX equivalents (later): `/sys/kernel/config/tsm/report` (configfs-tsm) to get a
quote, Intel **DCAP** or **Trust Authority** to verify. GPU (later): NVIDIA
**nvtrust** / NRAS. The `verify/` module abstracts all three behind one policy.

---

## 4. Phase 1 — replace the mock with the real verifier

This is the actual build task on the box. The swap-in points are already marked
in the code.

### 4.1 The binding contract (do not get this wrong)

The miner must put **exactly** these 64 bytes into the SNP report's
`REPORT_DATA`, and the verifier must check them:

```python
from cathedral.common import report_data
# 64 bytes = sha512(nonce || miner_hotkey  [|| ssh_host_key for Sandbox])
rd = report_data(nonce, miner_hotkey)          # -> pass as request-data.bin to snpguest
```

- **Freshness** comes from the validator's per-challenge `nonce` (32 bytes).
- **Ownership** comes from binding `miner_hotkey` — this defeats evidence relay
  (one attested machine fronting for many registered UIDs). See `docs/DESIGN.md §6`.

If `REPORT_DATA` in the returned report ≠ `report_data(nonce, hotkey)`, **reject**.

### 4.2 Next SNP runtime step — `cathedral/attest/__init__.py`

The remaining SNP runtime task is wiring a real collector into the scoring path.
That collector should:

1. compute `rd = report_data(nonce, hotkey, ssh_host_key)`, write to a temp file
2. shell out to `snpguest report <out> <rd-file>` (or call the sev-guest ioctl
   directly)
3. read the report bytes + fetch the cert chain
4. return an `Evidence(kind=SEV_SNP, quote=<report bytes>, cert_chain=[...],
   nonce=nonce, miner_hotkey=hotkey, ssh_host_key=ssh_host_key)`

### 4.3 Next SNP runtime step — `cathedral/verify/__init__.py`

SNP verification code exists now; the remaining runtime task is making the SNP
collector/verifier pair part of an enabled scoring path. The SNP verifier must:

1. verify the AMD signature chain (`snpguest verify`, or the `sev` Rust crate /
   a Python binding) — **this is the crypto you must not hand-roll**
2. parse the report; check `REPORT_DATA == report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)`
3. check `MEASUREMENT in policy.allowed_measurements` and `TCB >= policy.min_tcb`
4. return `Attested(tier=CC_CPU_SNP, chip_id=<CHIP_ID>, measurement=<...>, tcb=<...>)`
   or `None`

### 4.4 Wire it in

In `cathedral/neuron/validator.py` the epoch calls `miner.serve_evidence(...)`
(mock) → swap to a real axon request + `cathedral.verify.verify`. In
`cathedral/neuron/miner.py`, `MockMiner.serve_evidence` → real
`cathedral.attest.collect_snp`. Both swap points carry `Phase-1 swap-in`
comments. **Nothing else in the epoch changes** — the mock was built against the
real interface exactly so this is a drop-in.

### 4.5 The real first test (write this on the box)

```
tests/test_attest_snp_hw.py   (mark: requires /dev/sev-guest; skip otherwise)
  - collect_snp then verify round-trips to an Attested with a non-empty chip_id
  - a report whose REPORT_DATA was bound to a DIFFERENT nonce/hotkey is REJECTED
  - a measurement absent from policy.allowed_measurements is REJECTED
  - a report below policy.min_tcb is REJECTED
```

Guard it with `pytest.mark.skipif(not os.path.exists('/dev/sev-guest'))` so the
hardware-free tests still run everywhere and the HW test runs only on the box.

**Definition of done for the box:** `test_attest_snp_hw.py` green on the SNP VM,
and a validator epoch that admits a *real*-attested miner (mock replaced) and
produces weights. That is the first real proof the subnet gates on hardware.

---

## 5. Verification checklist

Track A (any box):
- [ ] `pip install -e '.[dev]'` succeeds
- [ ] `python -m pytest -q` matches the current count in `RUNTEST.md`
- [ ] `python scripts/demo_sat.py` → **PASS**

Track B (SNP box):
- [ ] `/dev/sev-guest` present; `dmesg | grep -i snp` shows guest active
- [ ] `snpguest report` produces a report bound to your `report_data` bytes
- [ ] `snpguest verify` passes the AMD cert chain
- [ ] `collect_snp` + `verify` round-trip to an `Attested` with a real `chip_id`
- [ ] wrong-nonce / wrong-hotkey report is **rejected**
- [ ] `test_attest_snp_hw.py` green on the box
- [ ] a validator epoch with the mock replaced still produces conserved weights

---

## 6. Repo map

```
docs/DESIGN.md            the founding design (products, lanes, emissions, attestation)
HANDOFF.md                this file
RUNTEST.md                per-command test breakdown
BUILD_SPEC.md             module responsibilities / file ownership from the build
proto/evidence.proto      TEE evidence wire schema (SNP | TDX | GPU_CC)

cathedral/
  common.py               tiers, Evidence/Attested types, issue_nonce, report_data  ← the binding
  census.py               CC capability probe (python -m cathedral.census)
  attest/__init__.py      collectors — collect_snp/tdx/gpu  ← Phase 1 (§4.2)
  verify/__init__.py      real verifier + policy            ← Phase 1 (§4.3)
  verify/mock.py          MOCK path used by the testable core (delete-worthy once real)
  lanes/__init__.py       Lane ABC + ROUTING_VECTOR
  lanes/sat.py            SAT lane: DPLL solver + self-certifying verifier + score
  lanes/sat_types.py      SAT dataclasses (DIMACS)
  economics.py            apply_routing: floor + routing-weighted work + burn = 1.0
  api.py                  in-process control plane: WorkQueue / Inventory / Allocator
  cli.py                  argparse CLI (census, verify-quote, work)
  neuron/validator.py     hardware-free epoch (mock)        ← swap-in at §4.4
  neuron/miner.py         MockMiner serves evidence + SAT   ← swap-in at §4.4

tests/                    hardware-free tests + hardware-gated TDX round trip
scripts/demo_sat.py       dispatch → solve → verify → PASS
```

---

## 7. Troubleshooting

- **`/dev/sev-guest` missing on a cloud VM** — the confidential-VM option was not
  enabled at create time. Recreate with SEV-SNP explicitly on (it defaults off).
- **`snpguest verify` fails on the cert chain** — check the box clock (KDS certs
  are time-sensitive) and that you fetched both `vcek` and `ca`. KDS is at
  `kdsintf.amd.com`; ensure outbound HTTPS is allowed.
- **REPORT_DATA mismatch** — you almost certainly serialized the hotkey or nonce
  differently on the miner vs. validator. Both sides must call
  `cathedral.common.report_data` with identical inputs; do not re-implement it.
- **Wrong measurement every boot** — the launch measurement changes if the guest
  image/firmware changes. For production, pin a known image and add its
  measurement to `Policy.allowed_measurements` (this is the whole point of the
  measured-image discipline in `docs/DESIGN.md §7`).
- **Tests fail after your edits** — the hardware-free tests are the contract;
  if your Phase-1 changes break them, you changed an interface, not just an
  implementation. Re-read the swap-in comments.

---

## 8. Procurement notes

- **Launch test:** the live GCP `c3` TDX CVM. Treat it as production-adjacent:
  collect a quote, verify it, and avoid service/config changes.
- **SNP test (next CPU port):** one cloud SNP CVM (Azure DCasv5 or GCP SEV-SNP),
  Ubuntu 24.04, ~$0.50–$2/hr. Tear it down after — this is a dev box, not
  standing supply.
- **GPU-CC test (later, hardest):** a bare-metal H100/H200 with CC mode, from a
  Latitude/Voltage-Park-tier provider; NVIDIA nvtrust for verification. Only
  needed for the Sandbox GPU tier — defer until CPU attestation is solid.

Keep dev hardware ephemeral. Standing confidential supply is what the *subnet*
recruits via emissions once attestation gating is live — you don't buy it.

---

## 9. What to hand the next builder

If you commission the box and want an agent (or a person) to do the Phase-1
build, point them at: this file §4, the two swap-in files
(`cathedral/attest/__init__.py`, `cathedral/verify/__init__.py`), the binding in
`cathedral/common.py`, and `docs/DESIGN.md §6`. The task is bounded and the
interface is frozen — it is "make `test_attest_snp_hw.py` green on the box
without changing the 40 existing tests."
