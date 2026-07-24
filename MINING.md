# Mining Cathedral

This guide is the shortest honest path from a new machine to an accepted
Cathedral worker.

> **Current status:** miner onboarding is operator-assisted on both networks.
> Mainnet SN39 is the live production lane and submits confidential weights on
> chain. Testnet SN292 is the non-paying integration lane for proving the same
> worker, attestation, work, scoring, and UID-mapping path before mainnet.

## What A Miner Does

A Cathedral miner runs an authenticated worker on an Intel TDX confidential
VM. Each epoch, Cathedral:

1. sends a fresh nonce;
2. requests a TDX quote bound to that nonce and the miner hotkey;
3. verifies the quote, measurement, security policy, and physical platform;
4. sends deterministic audit work;
5. verifies the result and derives the work units itself; and
6. includes the miner in a complete signed score vector.

Attestation permits the machine to compete. It does not earn by itself. Failed,
missing, stale, or unverifiable work receives zero.

## Before You Start

You need:

- an Intel TDX confidential VM that exposes Linux configfs-tsm;
- Ubuntu or another recent Linux distribution with Python 3.11 or newer;
- a Bittensor wallet and hotkey registered on **mainnet SN39** for live mining,
  or **testnet SN292** for non-paying integration testing;
- a public IPv4 address reachable by the selected Cathedral validator;
- Git and OpenSSL; and
- approval through the public
  [Miner beta request](https://github.com/cathedralai/cathedralconfidential/issues/new?template=miner-beta.yml)
  form. A maintainer supplies the validator source IP and arranges the private
  token exchange after accepting the request.

The current worker supports Intel TDX CPU only. AMD SEV-SNP and NVIDIA
Confidential Computing are not active mining paths yet.

Never send anyone your wallet seed, coldkey, or hotkey private key. The validator
needs only the public hotkey address, worker endpoint, and a worker-specific
bearer token.

## 1. Register The Hotkey

Register the same hotkey that the worker will serve. Choose one network; use
mainnet SN39 to compete for emissions or testnet SN292 to prove the setup
without emissions.

The command below uses the current `btcli` command layout. Check your installed
version with `btcli --version` before registering.

```bash
# Mainnet production
btcli subnet register \
  --network finney \
  --netuid 39 \
  --wallet-name <wallet-name> \
  --hotkey <hotkey-name>

# Testnet integration
btcli subnet register \
  --network test \
  --netuid 292 \
  --wallet-name <wallet-name> \
  --hotkey <hotkey-name>
```

Record its SS58 address. Use the **address**, not the local wallet or hotkey
name, as `HOTKEY_ADDRESS` below.

```bash
export HOTKEY_ADDRESS='<ss58-hotkey-address>'
```

Registration is necessary for admission, but it does not mean the worker is
reachable or earning.

## 2. Install Cathedral

```bash
git clone https://github.com/cathedralai/cathedralconfidential.git
cd cathedralconfidential

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Confirm the worker command is installed:

```bash
cathedral worker serve --help
```

## 3. Confirm Intel TDX

Run the read-only capability probe:

```bash
sudo "$PWD/.venv/bin/cathedral" census
sudo test -d /sys/kernel/config/tsm/report && echo 'configfs-tsm: ready'
```

The required result is:

```text
Intel TDX   : yes
=> CC-CAPABLE
```

Do not continue if Intel TDX reports `no`. A machine type advertised merely as
"confidential" may use a different technology that the current worker cannot
serve.

## 4. Create A Worker Token

Use a different random token for every worker. Store it with mode `0600` and do
not paste it into public chats, screenshots, issues, or logs.

```bash
install -d -m 700 "$HOME/.config/cathedral"
umask 077
openssl rand -hex 32 > "$HOME/.config/cathedral/worker-token"
export CATHEDRAL_WORKER_BEARER_TOKEN="$(tr -d '\n' < "$HOME/.config/cathedral/worker-token")"
```

## 5. Start The Worker

The current operator-assisted beta uses a temporary, explicitly marked
development bind so the selected network's validator can reach the worker:

```bash
sudo --preserve-env=CATHEDRAL_WORKER_BEARER_TOKEN \
  "$PWD/.venv/bin/cathedral" worker serve \
  --hotkey "$HOTKEY_ADDRESS" \
  --host 0.0.0.0 \
  --port 8081 \
  --development-allow-non-loopback
```

The process prints one startup object and then waits for validator requests:

```json
{"host": "0.0.0.0", "port": 8081, "hotkey": "<ss58-hotkey-address>"}
```

The token value is inherited through the environment and does not appear in
the command arguments. If local `sudo` policy rejects `--preserve-env`, stop and
configure a root-readable environment file rather than placing the token value
after `sudo env` or on the command line.

This beta command serves authenticated plain HTTP. Restrict TCP port `8081` to
the validator source IP in the cloud firewall. Do not expose it to the whole
internet. The token is not encrypted on the network in this beta and may be
visible to an on-path observer; the firewall allowlist and prompt rotation are
mandatory. Production workers will bind to loopback behind HTTPS and will not
use `--development-allow-non-loopback`.

The configfs TDX collector must be able to create report directories beneath
`/sys/kernel/config/tsm/report`. The current hardware proof runs the worker with
the required elevated permission; a narrower production service account is a
remaining hardening task.

The worker intentionally suppresses per-request access logs, so the terminal
stays quiet even when validator requests succeed. Keep the foreground process
and SSH session open for the first test. After acceptance, run the same command
under a supervisor such as systemd; do not leave the long-lived worker attached
to an ordinary SSH shell.

## 6. Prove The Worker Returns A Real Quote

In a second shell on the worker machine:

```bash
export HOTKEY_ADDRESS='<ss58-hotkey-address>'
export CATHEDRAL_WORKER_BEARER_TOKEN="$(tr -d '\n' < "$HOME/.config/cathedral/worker-token")"
NONCE="$(openssl rand -hex 32)"

curl -fsS http://127.0.0.1:8081/v1/evidence \
  -H "Authorization: Bearer $CATHEDRAL_WORKER_BEARER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"nonce_hex\":\"$NONCE\",\"assigned_hotkey\":\"$HOTKEY_ADDRESS\"}" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print("kind:", r["kind"]); print("quote bytes:", len(bytes.fromhex(r["quote_hex"]))); print("hotkey:", r["assigned_hotkey"])'
```

Expected shape:

```text
kind: tdx
quote bytes: <nonzero vendor quote size>
hotkey: <your ss58 hotkey address>
```

The live proof currently produces 8000-byte quotes, but miners should check for
a nonempty valid quote rather than hard-code that size.

## 7. Request Beta Enrollment

Self-service public enrollment is not deployed yet. First open a
[Miner beta request](https://github.com/cathedralai/cathedralconfidential/issues/new?template=miner-beta.yml).
The issue is public: include the public hotkey and non-secret hardware details,
but **never include the bearer token**. A maintainer will confirm beta capacity,
supply the validator source IP, and arrange a private channel for these three
values:

```text
network: mainnet SN39 or testnet SN292
hotkey:  <ss58-hotkey-address registered on that network>
endpoint: http://<public-ip>:8081
bearer token: <contents of ~/.config/cathedral/worker-token>
```

Do not post the bearer token publicly. The validator uses it only to authenticate
requests to this worker. Rotate it immediately if it appears in a screenshot,
shell history shared with others, or a public message.

The validator operator will confirm:

1. the hotkey is registered on the selected subnet;
2. the endpoint is reachable from the validator;
3. fresh TDX evidence verifies and matches the hotkey;
4. the physical platform is not already assigned to another hotkey;
5. deterministic audit work completes and verifies; and
6. the signed score vector contains the miner.

## 8. Know When It Is Working

Ask for the epoch result for your hotkey. A successful beta epoch has all of
these properties:

| Gate | Required result |
|---|---|
| Registration | Hotkey maps to exactly one UID on the selected subnet |
| Reachability | Validator can call the authenticated endpoint |
| Attestation | `admit=Y`; fresh TDX quote passes policy |
| Work | `work=verified`; validator-derived work units are positive |
| Score | Score is positive in the complete signed vector |
| Publication | Signed vector is accepted by the thin validator |
| Chain | SN39 submits live weights; SN292 remains non-paying dry-run |

Example validator-side outcome:

```text
[2026-07-13T15:23:09Z] OK  5Aaaa..aaaa  ep=7/1  admit=Y  work=verified  wu=20.00  score=1.000  pub=YES  ch=ababab..ababab
```

Mainnet chain submission is live. A miner earns only after its registered SN39
hotkey passes attestation and verified work and appears with positive weight in
the signed vector. Testnet SN292 results never imply token emissions.

### Confidential-GPU launch track

The first `cc_gpu` profile is a bounded Cathedral-operated GCP proof target, not
open miner enrollment. Do not advertise an H100, a provider VM, or a successful
local NVIDIA attestation as reward-eligible confidential-GPU supply. The
current GPU launch gate requires one Spot `a3-highgpu-1g` with Intel TDX and one
H100 to produce a fresh, policy-compliant Cathedral job receipt that an
independent validator accepts exactly once.

Until that live chain is `PASS`, CC-GPU registration, uptime, capacity offers,
synthetic receipts, and hybrid-GPU work earn no CC-GPU score or weight. When
miner enrollment opens, validators will reward only unique real jobs with the
selected receipt schema and current policy; stale, duplicate, mismatched,
hybrid-preview, or unverifiable evidence receives zero credit. The ordinary
TDX CPU mining lane above is unchanged.

## Troubleshooting

| Symptom | Meaning and next check |
|---|---|
| `Intel TDX : no` | Wrong VM type, guest kernel, or configfs-tsm support |
| `configfs-tsm report root not found` | `/sys/kernel/config/tsm/report` is unavailable in the guest |
| `plain worker HTTP must bind loopback` | Non-loopback HTTP requires the beta-only development flag; production requires HTTPS |
| HTTP `401` | Validator and worker bearer tokens differ |
| HTTP `403 assigned_hotkey mismatch` | Worker was started with a different hotkey address |
| HTTP `500 evidence collection failed` | Check TDX availability and permission to write the configfs report directory |
| Endpoint unreachable | Check cloud firewall, public IP, process, and port `8081` |
| Enrollment rejected | Confirm the hotkey is registered on the selected subnet and the endpoint uses the expected public IP |
| `admit=N` | Quote crypto, measurement, TCB, hotkey binding, or platform policy failed |
| `score=0` | No verified work, stale evidence, failed work, or explicit revocation |

## What Comes Next

The live operator-assisted path still needs:

- public self-service signed enrollment;
- a production HTTPS worker deployment without development flags;
- a positive-miner-to-zero on-chain revocation acceptance test; and
- published self-service policy and onboarding endpoints.

The current source of truth is [`BUILD_STATUS.md`](BUILD_STATUS.md). If that
file and an announcement disagree, follow `BUILD_STATUS.md`.
