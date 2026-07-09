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

Continue only if `cc_capable` is `true`. For the current Confidential lane,
enrollment requires both SEV-SNP guest evidence and GPU CC evidence. The GPU
collector/verifier is still fail-closed, so SNP-only boxes will not reach
`VERIFIED`.

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
Until GPU CC collection is implemented, this endpoint returns 503 rather than
serving SNP-only admission evidence.

## 3. Enroll

From any machine that can reach the registry:

```bash
export REGISTRY_URL='https://REGISTRY_HOST'
export MINER_ENDPOINT='http://YOUR_MINER_HOST:8090'
export ENROLL_NONCE="$(openssl rand -hex 16)"
export ENROLL_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export ENROLL_BODY="$(python - <<'PY'
import json, os
payload = {
    "endpoint_url": os.environ["MINER_ENDPOINT"],
    "hotkey": os.environ["CATHEDRAL_HOTKEY"],
    "nonce": os.environ["ENROLL_NONCE"],
    "timestamp": os.environ["ENROLL_TIMESTAMP"],
}
print(json.dumps(payload, separators=(",", ":"), sort_keys=True), end="")
PY
)"
# Sign ENROLL_BODY with the sr25519 hotkey that owns CATHEDRAL_HOTKEY.
export ENROLL_SIGNATURE_B64='BASE64_SR25519_SIGNATURE'
curl -fsS -X POST "$REGISTRY_URL/v1/enroll" \
  -H 'content-type: application/json' \
  -d "{\"hotkey\":\"$CATHEDRAL_HOTKEY\",\"endpoint_url\":\"$MINER_ENDPOINT\",\"nonce\":\"$ENROLL_NONCE\",\"timestamp\":\"$ENROLL_TIMESTAMP\",\"signature_b64\":\"$ENROLL_SIGNATURE_B64\"}"
```

## 4. Confirm Attestation

After the next probe cycle:

```bash
curl -fsS "$REGISTRY_URL/v1/attested"
```

Your row should show `verification_status: "VERIFIED"` only after both SNP and
GPU CC evidence verify. Verified rows expire after the registry verification TTL
(default: 1 hour) unless the prober refreshes them. The public `count` field is
the distinct, fresh verified chip count that drives the Confidential lane
emissions schedule.
