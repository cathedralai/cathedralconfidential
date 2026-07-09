# Cathedral Confidential Miner Onboarding

Run these commands on your TEE miner box.

## 1. Check Hardware

```bash
git clone https://github.com/cathedralai/cathedralconfidential.git
cd cathedralconfidential
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m cathedral.census --json
```

Continue only if `cc_capable` is `true`. For SEV-SNP, `/dev/sev-guest` and
`snpguest` must be available.

## 2. Run The Miner Evidence Server

Set your Bittensor hotkey SS58 address and the public host/port validators can
reach:

```bash
export CATHEDRAL_HOTKEY='YOUR_SS58_HOTKEY'
python -m cathedral.neuron.miner \
  --hotkey "$CATHEDRAL_HOTKEY" \
  --host 0.0.0.0 \
  --port 8090
```

Keep this process running. It serves validator challenges at `/v1/evidence`.

## 3. Enroll

From any machine that can reach the registry:

```bash
export REGISTRY_URL='https://REGISTRY_HOST'
export MINER_ENDPOINT='http://YOUR_MINER_HOST:8090'
curl -fsS -X POST "$REGISTRY_URL/v1/enroll" \
  -H 'content-type: application/json' \
  -d "{\"hotkey\":\"$CATHEDRAL_HOTKEY\",\"endpoint_url\":\"$MINER_ENDPOINT\"}"
```

## 4. Confirm Attestation

After the next probe cycle:

```bash
curl -fsS "$REGISTRY_URL/v1/attested"
```

Your row should show `verification_status: "VERIFIED"`. The public `count`
field is the distinct verified chip count that drives the Confidential lane
emissions schedule.
