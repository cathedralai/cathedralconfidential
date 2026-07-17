# Assurance claims

Cathedral reports four independent assurance claims. A claim has one status:
`not_evaluated`, `passed`, `failed`, `stale`, or `revoked`.

| Claim | A passing claim means | It does not mean |
|---|---|---|
| `hardware` | Vendor-backed evidence identifies an accepted confidential-compute platform and security state. | The approved Cathedral workload ran or returned a correct result. |
| `software` | The measured software configuration matched the policy snapshot used for verification. | The validator checked a particular output or the customer used a protected channel. |
| `channel` | The live endpoint owns the channel key bound into fresh attestation evidence. | The application result is correct. |
| `work` | The named validator challenge and returned certificate passed that lane's independent verification. | Every possible application output is correct. |

Each evaluated claim carries its own evidence digest, policy digest, and UTC
verification time. `not_evaluated` claims carry `null` audit fields. Failure
detail exposed publicly is limited to stable reason categories; raw quotes,
tokens, customer payloads, endpoint addresses, and physical identifiers do not
belong in a public assurance response.

Authorization code must name the claims it requires:

- attestation admission requires `hardware=passed` and `software=passed`;
- key release and protected work dispatch require `hardware=passed`,
  `software=passed`, and `channel=passed`;
- score eligibility requires `hardware=passed`, `software=passed`, and
  `work=passed`;
- receipt issuance is allowed for success and failure outcomes because the
  receipt records the individual statuses rather than inventing an overall
  success flag.

The compatibility field `verification_status` remains available while callers
migrate, but it is not an authorization policy and it cannot set any of the
four claims. Attestation grants admission; validator-verified work determines
credit. Neither statement claims universal application correctness.

New work lanes must document which evidence sets the `work` claim to `passed`,
how the validator independently checks it, and which failure category is safe
to expose publicly.
