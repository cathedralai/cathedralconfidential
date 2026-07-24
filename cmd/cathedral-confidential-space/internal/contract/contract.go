package contract

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ProfileID                         = "gcp-a3-high-h100-tdx-v1"
	ChallengeSchema                   = "cathedral_confidential_space_challenge_v1"
	EvidenceSchema                    = "cathedral_confidential_space_token_evidence_v1"
	ReadySchema                       = "cathedral_confidential_space_gpu_ready_v1"
	SignedProofSchema                 = "cathedral_confidential_space_channel_proof_v1"
	ExpectedSchema                    = "cathedral_cc_gpu_backend_request_v1"
	MaxDocumentBytes                  = 32 * 1024 * 1024
	ChannelProofDomain                = "cathedral-confidential-space-channel-proof-v1\x00"
	ChannelBindDomain                 = "cathedral-confidential-space-channel-binding-v1\x00"
	KBSChallengeRequestSchema         = "cathedral_cc_gpu_kbs_challenge_request_v1"
	KBSChallengeSchema                = "cathedral_cc_gpu_kbs_challenge_v1"
	KBSReleaseSubmitSchema            = "cathedral_cc_gpu_kbs_release_submit_v1"
	KBSReleaseResponseSchema          = "cathedral_cc_gpu_kbs_release_response_v1"
	KBSReleaseRequestSchema           = "cathedral_cc_gpu_kbs_release_request_v1"
	KBSReleaseAckSchema               = "cathedral_cc_gpu_kbs_release_ack_v1"
	KBSCompletionStartSchema          = "cathedral_cc_gpu_kbs_completion_start_v1"
	KBSCompletionAckSchema            = "cathedral_cc_gpu_kbs_completion_ack_v1"
	KBSReleasePolicySchema            = "cathedral_cc_gpu_kbs_release_policy_v1"
	MaxProtectedPlaintextBytes  int64 = 32 * 1024 * 1024 * 1024
	MaxProtectedCiphertextBytes int64 = 33 * 1024 * 1024 * 1024
	ProtectedTmpfsReserveBytes  int64 = 1024 * 1024 * 1024
	MaxVectorPlaintextBytes     int64 = 256 * 1024 * 1024
)

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Challenge struct {
	Phase          string
	Expected       map[string]any
	FinalizeSHA256 any
	Canonical      []byte
	Digest         string
}

func ValidateReleasePolicy(raw []byte, expected map[string]any, now time.Time) (map[string]any, error) {
	value, err := StrictJSON(raw)
	document, ok := value.(map[string]any)
	request, requestOK := expected["request"].(map[string]any)
	inputs, inputsOK := request["protected_inputs"].([]any)
	if err != nil || !ok || !requestOK || !inputsOK || !ExactKeys(document, "schema", "execution_class", "profile_id", "owner_digest", "job_id", "attempt_id", "job_context_digest", "protected_input_set_digest", "sealed_record_sha256s", "output_recipient_digest", "issued_at", "expires_at", "signing_key_id", "signature") || document["schema"] != KBSReleasePolicySchema || document["owner_digest"] != expected["owner_digest"] || document["job_id"] != expected["job_id"] || document["attempt_id"] != expected["attempt_id"] || document["job_context_digest"] != expected["job_context_digest"] || document["execution_class"] != "cc_gpu" || document["profile_id"] != ProfileID || document["protected_input_set_digest"] != request["protected_input_set_digest"] {
		return nil, errors.New("KBS release policy has an invalid exact job binding")
	}
	recipientRaw, _ := CanonicalJSON(request["output_recipient"])
	if document["output_recipient_digest"] != Digest(recipientRaw) {
		return nil, errors.New("KBS release policy output recipient digest is mismatched")
	}
	signingKeyID, keyOK := document["signing_key_id"].(string)
	signature, signatureOK := document["signature"].(map[string]any)
	if !keyOK || signingKeyID == "" || !signatureOK || !ExactKeys(signature, "algorithm", "value_base64") || signature["algorithm"] != "ed25519" {
		return nil, errors.New("KBS release policy signature schema is invalid")
	}
	digests, digestsOK := document["sealed_record_sha256s"].([]any)
	if !digestsOK || len(digests) != len(inputs) {
		return nil, errors.New("KBS release policy sealed record set is invalid")
	}
	for index, rawInput := range inputs {
		input, inputOK := rawInput.(map[string]any)
		if !inputOK || digests[index] != input["sealed_record_sha256"] {
			return nil, errors.New("KBS release policy sealed record order is mismatched")
		}
	}
	issuedText, issuedOK := document["issued_at"].(string)
	issued, issuedErr := time.Parse("2006-01-02T15:04:05.000000Z", issuedText)
	expiresText, expiresOK := document["expires_at"].(string)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05.000000Z", expiresText)
	if !issuedOK || issuedErr != nil || issued.Format("2006-01-02T15:04:05.000000Z") != issuedText || !expiresOK || expiresErr != nil || expires.Format("2006-01-02T15:04:05.000000Z") != expiresText || !expires.After(issued) || expires.Sub(issued) > 10*time.Minute || now.Before(issued.Add(-30*time.Second)) || now.After(expires.Add(30*time.Second)) {
		return nil, errors.New("KBS release policy is expired, future-overlong, or non-canonical")
	}
	return document, nil
}

type LocalGPU struct {
	Model      string
	UUIDSHA256 string
	Count      int
	Ready      bool
}

func StrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := strictValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON contains trailing data")
	}
	return value, nil
}

func strictValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		value := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON key is invalid")
			}
			if _, exists := value[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			child, err := strictValue(decoder)
			if err != nil {
				return nil, err
			}
			value[key] = child
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("JSON object is incomplete")
		}
		return value, nil
	case '[':
		value := []any{}
		for decoder.More() {
			child, err := strictValue(decoder)
			if err != nil {
				return nil, err
			}
			value = append(value, child)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("JSON array is incomplete")
		}
		return value, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func CanonicalJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func ExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := value[key]; !present {
			return false
		}
	}
	return true
}

func Digest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func HexDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func ValidDigest(value any) bool {
	text, ok := value.(string)
	return ok && digestRE.MatchString(text)
}

func ValidHex(value any) bool {
	text, ok := value.(string)
	return ok && hexRE.MatchString(text)
}

func ValidUUID(value any) bool {
	text, ok := value.(string)
	return ok && uuidRE.MatchString(text)
}

func ParseChallenge(data []byte, actionPhase string) (*Challenge, error) {
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return nil, errors.New("challenge is empty or exceeds 32 MiB")
	}
	value, err := StrictJSON(data)
	if err != nil {
		return nil, errors.New("challenge is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !ExactKeys(document, "schema", "phase", "expected", "finalize_sha256") || document["schema"] != ChallengeSchema {
		return nil, errors.New("challenge has an invalid exact schema")
	}
	phase, ok := document["phase"].(string)
	if !ok || (phase != "admission" && phase != "completion") || actionPhase != "" && actionPhase != phase {
		return nil, errors.New("challenge phase is invalid or mismatched")
	}
	expected, ok := document["expected"].(map[string]any)
	if !ok {
		return nil, errors.New("challenge expected contract is invalid")
	}
	if err := ValidateExpected(expected, phase); err != nil {
		return nil, err
	}
	if phase == "admission" && document["finalize_sha256"] != nil {
		return nil, errors.New("admission cannot carry a finalize object digest")
	}
	if phase == "completion" && !ValidDigest(document["finalize_sha256"]) {
		return nil, errors.New("completion requires the immutable finalize object digest")
	}
	canonical, _ := CanonicalJSON(document)
	return &Challenge{Phase: phase, Expected: expected, FinalizeSHA256: document["finalize_sha256"], Canonical: canonical, Digest: Digest(canonical)}, nil
}

func ValidateExpected(expected map[string]any, phase string) error {
	keys := []string{
		"schema", "execution_class", "profile_id", "profile_authority", "subject_hotkey", "evidence_format",
		"provider", "machine_type", "project_id", "zone", "gpu_type", "gpu_count",
		"provisioning_model", "provider_resource_id", "provider_instance_id", "source_image", "workload_service_account", "attestation_audience",
		"worker_id", "job_id", "attempt_id", "attempt_sequence",
		"owner_digest", "job_context_digest", "admission_nonce_digest", "request", "remaining_spend_micros",
		"phase", "nonce_digest", "channel_key_sha256", "channel_binding_sha256", "verifier_digest",
	}
	if phase == "completion" {
		keys = append(keys, "result_sha256", "artifact_manifest_sha256", "admission_bundle_sha256", "admission_gpu_identity_set_sha256", "kbs_release_ack_sha256")
	}
	if !ExactKeys(expected, keys...) || expected["schema"] != ExpectedSchema || expected["execution_class"] != "cc_gpu" || expected["profile_id"] != ProfileID || expected["provider"] != "gcp" || expected["machine_type"] != "a3-highgpu-1g" || expected["zone"] != "us-central1-a" || expected["gpu_type"] != "nvidia_h100_80gb" || expected["phase"] != phase {
		return errors.New("expected contract is outside the supported exact profile")
	}
	if expected["provisioning_model"] != "spot" {
		return errors.New("first Confidential Space CC-GPU profile is SPOT-only")
	}
	if expected["evidence_format"] != "google_cloud_attestation_pki" {
		return errors.New("first Confidential Space profile requires Google Cloud Attestation PKI evidence")
	}
	for _, key := range []string{"provider_resource_id", "provider_instance_id", "source_image", "workload_service_account", "attestation_audience"} {
		value, ok := expected[key].(string)
		if !ok || value == "" || value != strings.TrimSpace(value) || len(value) > 4096 {
			return fmt.Errorf("expected %s is invalid", key)
		}
	}
	if _, err := strconv.ParseUint(expected["provider_instance_id"].(string), 10, 64); err != nil {
		return errors.New("expected provider_instance_id is not a numeric GCE instance ID")
	}
	if expected["gpu_count"] != json.Number("1") && expected["gpu_count"] != 1 {
		return errors.New("expected contract requires exactly one GPU")
	}
	for _, key := range []string{"worker_id", "job_id", "attempt_id"} {
		value, ok := expected[key].(string)
		if !ok || !uuidRE.MatchString(value) {
			return fmt.Errorf("expected %s is not a canonical UUID", key)
		}
	}
	for _, key := range []string{"owner_digest", "job_context_digest", "admission_nonce_digest", "nonce_digest", "verifier_digest"} {
		if !ValidDigest(expected[key]) {
			return fmt.Errorf("expected %s is not a canonical digest", key)
		}
	}
	if phase == "admission" {
		if expected["nonce_digest"] != expected["admission_nonce_digest"] || expected["channel_key_sha256"] != nil || expected["channel_binding_sha256"] != nil {
			return errors.New("admission nonce or new-channel contract is invalid")
		}
	} else {
		if expected["nonce_digest"] == expected["admission_nonce_digest"] {
			return errors.New("completion reuses the admission nonce")
		}
		for _, key := range []string{"channel_key_sha256", "channel_binding_sha256", "result_sha256", "artifact_manifest_sha256", "admission_bundle_sha256", "admission_gpu_identity_set_sha256", "kbs_release_ack_sha256"} {
			if !ValidHex(expected[key]) {
				return fmt.Errorf("completion %s is invalid", key)
			}
		}
	}
	request, ok := expected["request"].(map[string]any)
	if !ok || !ExactKeys(request, "image", "image_digest", "command", "protected_inputs", "protected_input_set_digest", "artifacts", "output_recipient", "maximum_runtime_seconds", "maximum_output_bytes", "retry_policy", "policy") || request["retry_policy"] != "restart_from_zero" || !ValidDigest(request["image_digest"]) || !ValidDigest(request["protected_input_set_digest"]) {
		return errors.New("expected job request is invalid")
	}
	protectedInputs, ok := request["protected_inputs"].([]any)
	if !ok || len(protectedInputs) != 2 {
		return errors.New("first profile requires exactly one input and one model")
	}
	sealedReferences := map[string]bool{}
	var totalCiphertextBytes int64
	var totalPlaintextBytes int64
	for index, raw := range protectedInputs {
		input, ok := raw.(map[string]any)
		kind, kindOK := input["kind"].(string)
		reference, referenceOK := input["sealed_reference"].(string)
		cipherBytes, cipherErr := positiveInt64(input["ciphertext_bytes"])
		plainBytes, plainErr := positiveInt64(input["plaintext_bytes"])
		if !ok || !ExactKeys(input, "kind", "owner_digest", "sealed_reference", "sealed_record_sha256", "ciphertext_digest_sha256", "plaintext_digest_sha256", "ciphertext_bytes", "plaintext_bytes") || !kindOK || kind != "input" && kind != "model" && kind != "secret" || input["owner_digest"] != expected["owner_digest"] || !referenceOK || sealedReferences[reference] || !ValidDigest(input["sealed_record_sha256"]) || !ValidSealedReference(reference, input["ciphertext_digest_sha256"]) || !ValidDigest(input["plaintext_digest_sha256"]) || cipherErr != nil || plainErr != nil || cipherBytes > MaxProtectedCiphertextBytes || plainBytes > MaxProtectedPlaintextBytes {
			return errors.New("expected protected input declaration is invalid or duplicated")
		}
		if index == 0 && kind != "input" || index == 1 && kind != "model" {
			return errors.New("first profile protected inputs must be ordered input then model")
		}
		if plainBytes > MaxVectorPlaintextBytes {
			return errors.New("first fixed CUDA workload limits each float32 vector to 256 MiB")
		}
		if totalCiphertextBytes > MaxProtectedCiphertextBytes-cipherBytes || totalPlaintextBytes > MaxProtectedPlaintextBytes-plainBytes {
			return errors.New("expected protected input aggregate exceeds the first-profile bound")
		}
		totalCiphertextBytes += cipherBytes
		totalPlaintextBytes += plainBytes
		sealedReferences[reference] = true
	}
	protectedRaw, _ := CanonicalJSON(protectedInputs)
	if request["protected_input_set_digest"] != Digest(protectedRaw) {
		return errors.New("expected protected input set digest is mismatched")
	}
	command, ok := request["command"].([]any)
	if !ok || len(command) != 2 || command[0] != "/usr/bin/python3" || command[1] != "/opt/cathedral/bin/cathedral-job" {
		return errors.New("expected workload command is invalid")
	}
	for _, raw := range command {
		argument, ok := raw.(string)
		if !ok || argument == "" || len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 {
			return errors.New("expected workload command is not an absolute measured workload path")
		}
	}
	maximumRuntime, err := positiveInt64(request["maximum_runtime_seconds"])
	if err != nil || maximumRuntime < 1 || maximumRuntime > 24*60*60 {
		return errors.New("expected maximum runtime is invalid")
	}
	maximumOutput, err := positiveInt64(request["maximum_output_bytes"])
	if err != nil || maximumOutput != 262144 {
		return errors.New("expected maximum output bound is invalid")
	}
	artifacts, ok := request["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		return errors.New("expected artifact declarations are invalid")
	}
	artifactNames := map[string]bool{}
	resultCount := 0
	for _, raw := range artifacts {
		artifact, ok := raw.(map[string]any)
		name, nameOK := artifact["path"].(string)
		kind, kindOK := artifact["kind"].(string)
		bound, boundErr := positiveInt64(artifact["max_bytes"])
		if !ok || !ExactKeys(artifact, "path", "kind", "max_bytes") || !nameOK || name == "" || strings.ContainsAny(name, "/\\\x00") || artifactNames[name] || !kindOK || kind != "result" && kind != "artifact" || boundErr != nil || bound < 1 || bound > maximumOutput {
			return errors.New("expected artifact declaration is invalid or duplicated")
		}
		artifactNames[name] = true
		if kind == "result" {
			resultCount++
		}
	}
	if resultCount != 1 {
		return errors.New("expected artifact set must declare exactly one primary result")
	}
	primary := artifacts[0].(map[string]any)
	if primary["path"] != "result.json" || primary["kind"] != "result" || primary["max_bytes"] != json.Number("262144") && primary["max_bytes"] != 262144 {
		return errors.New("first profile requires exactly result.json with a 262144 byte bound")
	}
	recipient, ok := request["output_recipient"].(map[string]any)
	if !ok || !ExactKeys(recipient, "algorithm", "key_id", "public_key_base64") || recipient["algorithm"] != "x25519-hkdf-sha256-aes256gcm" {
		return errors.New("expected output recipient is invalid")
	}
	keyID, keyOK := recipient["key_id"].(string)
	publicKey, publicKeyOK := recipient["public_key_base64"].(string)
	if !keyOK || keyID == "" || len(keyID) > 256 || !publicKeyOK || len(publicKey) != 44 {
		return errors.New("expected output recipient identity is invalid")
	}
	decodedKey, decodeErr := base64.StdEncoding.Strict().DecodeString(publicKey)
	if decodeErr != nil || len(decodedKey) != 32 || base64.StdEncoding.EncodeToString(decodedKey) != publicKey {
		return errors.New("expected output recipient public key is invalid")
	}
	recipientKey, recipientErr := ecdh.X25519().NewPublicKey(decodedKey)
	probePrivateBytes := make([]byte, 32)
	probePrivateBytes[0] = 1
	probePrivate, probeErr := ecdh.X25519().NewPrivateKey(probePrivateBytes)
	if recipientErr != nil || probeErr != nil {
		return errors.New("expected output recipient public key is invalid")
	}
	shared, sharedErr := probePrivate.ECDH(recipientKey)
	if sharedErr != nil {
		return errors.New("expected output recipient public key is low-order")
	}
	for index := range shared {
		shared[index] = 0
	}
	policy, ok := request["policy"].(map[string]any)
	if !ok || policy["egress"] != "control_plane_only" {
		return errors.New("job must use control_plane_only egress")
	}
	endpoints, ok := policy["control_plane_endpoints"].([]any)
	if !ok || len(endpoints) != 2 {
		return errors.New("job must pin exactly the control-store and KBS endpoints")
	}
	seen := map[string]bool{}
	for _, raw := range endpoints {
		endpoint, ok := raw.(map[string]any)
		if !ok || !ExactKeys(endpoint, "purpose", "origin", "trust_anchor_sha256") {
			return errors.New("control-plane endpoint schema is invalid")
		}
		purpose, _ := endpoint["purpose"].(string)
		origin, _ := endpoint["origin"].(string)
		if (purpose != "control_store" && purpose != "kbs") || seen[purpose] || !strings.HasPrefix(origin, "https://") || strings.ContainsAny(strings.TrimPrefix(origin, "https://"), "/?#@") || !ValidDigest(endpoint["trust_anchor_sha256"]) {
			return errors.New("control-plane endpoint is invalid")
		}
		seen[purpose] = true
	}
	if !seen["control_store"] || !seen["kbs"] {
		return errors.New("control-plane endpoint set is incomplete")
	}
	return nil
}

// ValidSealedReference requires immutable ciphertext to live at a same-name
// SHA-256 content-addressed object. The KBS sealed record separately binds the
// key, nonce prefix, plaintext digest, sizes, and this immutable object digest.
func ValidSealedReference(reference string, ciphertextDigest any) bool {
	digest, ok := ciphertextDigest.(string)
	if !ok || !ValidDigest(digest) || !strings.HasPrefix(reference, "gs://") || strings.ContainsAny(reference, "?#\x00") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(reference, "gs://"), "/")
	if len(parts) < 4 || parts[0] == "" || parts[len(parts)-3] != "sealed-inputs" || parts[len(parts)-2] != "sha256" {
		return false
	}
	return parts[len(parts)-1] == strings.TrimPrefix(digest, "sha256:")+".ccgpu"
}

func positiveInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case json.Number:
		return strconv.ParseInt(string(typed), 10, 64)
	case int:
		if typed < 0 {
			return 0, errors.New("negative integer")
		}
		return int64(typed), nil
	case int64:
		return typed, nil
	default:
		return 0, errors.New("value is not an integer")
	}
}

func ChannelBinding(publicKey ed25519.PublicKey, expected map[string]any) string {
	input := bytes.NewBufferString(ChannelBindDomain)
	input.Write(publicKey)
	input.WriteString(expected["job_context_digest"].(string))
	input.WriteString(expected["attempt_id"].(string))
	return HexDigest(input.Bytes())
}

func ReadyAssertion(challenge *Challenge, publicKey ed25519.PublicKey, gpu LocalGPU) (map[string]any, error) {
	if gpu.Count != 1 || gpu.Model != "NVIDIA H100 80GB" || !gpu.Ready || !ValidDigest(gpu.UUIDSHA256) {
		return nil, errors.New("local GPU Ready assertion is not launch-admissible")
	}
	channelKey := HexDigest(publicKey)
	binding := ChannelBinding(publicKey, challenge.Expected)
	if challenge.Phase == "completion" && (challenge.Expected["channel_key_sha256"] != channelKey || challenge.Expected["channel_binding_sha256"] != binding) {
		return nil, errors.New("completion channel changed after admission")
	}
	return map[string]any{
		"schema": ReadySchema, "phase": challenge.Phase,
		"job_context_digest": challenge.Expected["job_context_digest"],
		"nonce_digest":       challenge.Expected["nonce_digest"],
		"channel_key_sha256": channelKey, "channel_binding_sha256": binding,
		"gpu_count": 1, "gpu_model": gpu.Model, "gpu_uuid_sha256": gpu.UUIDSHA256,
		"gpu_ready_state": "ready",
	}, nil
}

func nonce(label string, value any) (string, error) {
	encoded, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("cathedral-confidential-space-nonce-v1\x00"+label+"\x00"), encoded...))
	result := "c1" + label + "." + base64.RawURLEncoding.EncodeToString(digest[:])
	if len(result) < 8 || len(result) > 88 {
		return "", errors.New("attestation nonce is outside the Confidential Space bound")
	}
	return result, nil
}

func TokenNonces(challenge *Challenge, tlsEKM []byte, ready map[string]any) ([]string, error) {
	if len(tlsEKM) < 32 || len(tlsEKM) > 256 {
		return nil, errors.New("TLS exported key material is outside the channel-binding bound")
	}
	return TokenNoncesFromEKMDigest(challenge, Digest(tlsEKM), ready)
}

func TokenNoncesFromEKMDigest(challenge *Challenge, tlsEKMSHA256 string, ready map[string]any) ([]string, error) {
	if !ValidDigest(tlsEKMSHA256) {
		return nil, errors.New("TLS exported key material digest is invalid")
	}
	values := []struct {
		label string
		value any
	}{
		{"f", challenge.Expected["nonce_digest"]},
		{"j", map[string]any{"job_context_digest": challenge.Expected["job_context_digest"], "attempt_id": challenge.Expected["attempt_id"], "phase": challenge.Phase}},
		{"e", tlsEKMSHA256},
		{"r", ready},
	}
	if challenge.Phase == "completion" {
		values = append(values,
			struct {
				label string
				value any
			}{"o", map[string]any{
				"result_sha256": challenge.Expected["result_sha256"], "artifact_manifest_sha256": challenge.Expected["artifact_manifest_sha256"],
				"admission_bundle_sha256": challenge.Expected["admission_bundle_sha256"], "admission_gpu_identity_set_sha256": challenge.Expected["admission_gpu_identity_set_sha256"],
				"kbs_release_ack_sha256": challenge.Expected["kbs_release_ack_sha256"],
			}},
			struct {
				label string
				value any
			}{"z", challenge.FinalizeSHA256},
		)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		encoded, err := nonce(item.label, item.value)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	if len(result) > 6 {
		return nil, errors.New("attestation request exceeds the six-nonce limit")
	}
	return result, nil
}

func SignedProof(challenge *Challenge, token string, nonces []string, ready map[string]any, tlsEKM []byte, privateKey ed25519.PrivateKey) (map[string]any, error) {
	proof := map[string]any{
		"schema": SignedProofSchema, "phase": challenge.Phase,
		"challenge_sha256": challenge.Digest, "attestation_token_sha256": Digest([]byte(token)),
		"attested_nonces": stringsToAny(nonces), "ready_assertion": ready,
		"tls_ekm_sha256": Digest(tlsEKM),
	}
	encoded, err := CanonicalJSON(proof)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, append([]byte(ChannelProofDomain), encoded...))
	return map[string]any{
		"schema": EvidenceSchema, "phase": challenge.Phase, "attestation_token": token,
		"channel_proof":             proof,
		"channel_public_key_base64": base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		"channel_signature_base64":  base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
