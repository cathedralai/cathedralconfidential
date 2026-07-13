# Cathedral

**Confidential compute on Bittensor SN39.**

Cathedral turns independently operated Intel TDX and NVIDIA Confidential
Computing machines into a network for private workloads and long-running
agents. Miners earn for useful compute that Cathedral can attest and verify.

## How It Works

```text
Client job or agent
        |
        v
Cathedral scheduler  --->  Attested miner  --->  Output + signed receipt
        |                       ^
        |                       |
        +---- fresh audit ------+
        |
        v
Verifier  --->  Complete Cathedral score vector  --->  SN39 validators
                                                        |
                                                        v
                                                  Bittensor weights
```

1. A miner enrolls a registered SN39 hotkey and an authenticated worker
   endpoint.
2. Cathedral sends a fresh nonce and verifies the worker's vendor-backed
   hardware quote, measurement, security level, and hotkey binding.
3. The scheduler assigns customer workloads, deployed agents, and unpredictable
   audit tasks to admitted workers.
4. The verifier checks delivery and derives credit from the job and receipt.
   Miners never declare their own score.
5. Missing, failed, stale, or revoked work receives zero.
6. Cathedral publishes one signed, complete compute vector. SN39 validators
   verify the stream, map hotkeys to UIDs, and set weights.

The compute stream is Cathedral's entire score vector. It is not mixed with a
second scoring mechanism or limited to a reserved share.

## Mining

Miners serve confidential compute from their own infrastructure. Cathedral
never requires root access or operator SSH.

| Hardware | Role |
|---|---|
| Intel TDX CPU | Launch worker and confidential control plane |
| NVIDIA H100/H200 in CC mode | Confidential GPU workloads |
| NVIDIA B200-class systems | Future platform after attestation policy is qualified |

Hardware attestation grants admission. Emissions come from verified delivery:
customer jobs, agent uptime, inference, evaluation, batch compute, and audit
work.

```bash
cathedral worker --help
cathedral work status
```

## Validating

Cathedral validators consume the dedicated signed compute stream. They verify
its signature and freshness, require a complete hotkey-to-UID mapping, reject
identity conflicts, and submit the resulting SN39 weight vector.

```bash
cathedral runtime --help
```

## Run Locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
```

The local runtime includes TDX evidence collection and policy verification,
signed enrollment, authenticated workers, deterministic audit work,
validator-derived accounting, complete score reports, and zero revocation.

## Documentation

- [`BUILD_STATUS.md`](BUILD_STATUS.md) - current live proof and testnet boundary
- [`docs/DESIGN.md`](docs/DESIGN.md) - protocol and scoring design
- [`docs/TDX_LAUNCH.md`](docs/TDX_LAUNCH.md) - Intel TDX deployment
- [`HANDOFF.md`](HANDOFF.md) - operator setup
- [`RUNTEST.md`](RUNTEST.md) - test commands

## License

MIT
