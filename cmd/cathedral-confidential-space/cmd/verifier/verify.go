package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	issuer               = "https://confidentialcomputing.googleapis.com"
	verdictBundleSchema  = "cathedral_confidential_space_verified_bundle_v1"
	gpuIdentitySetSchema = "cathedral_google_nvidia_gpu_identity_set_v1"
	fingerprintDomain    = "cathedral-cc-gpu-evidence-fingerprint-v1\x00"
	maxTokenBytes        = 2 * 1024 * 1024
)

type verifiedToken struct {
	raw            string
	claims         map[string]any
	tdx            map[string]any
	nvidia         map[string]any
	gpuIdentitySet map[string]any
}

func verifyInput(raw []byte, phase string, policy *verifierPolicy, now time.Time, verifierDigest string) (map[string]any, error) {
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return nil, errors.New("verifier input is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document, "expected", "evidence", "tls_ekm_sha256", "finalize_sha256") || !contract.ValidDigest(document["tls_ekm_sha256"]) {
		return nil, errors.New("verifier input has an invalid exact schema")
	}
	expected, ok := document["expected"].(map[string]any)
	if !ok {
		return nil, errors.New("verifier expected contract is invalid")
	}
	challengeDocument := map[string]any{
		"schema": contract.ChallengeSchema, "phase": phase, "expected": expected,
		"finalize_sha256": document["finalize_sha256"],
	}
	challengeRaw, _ := contract.CanonicalJSON(challengeDocument)
	challenge, err := contract.ParseChallenge(challengeRaw, phase)
	if err != nil {
		return nil, err
	}
	if expected["profile_authority"] != policy.ProfileAuthority || expected["project_id"] != policy.ProjectID || expected["zone"] != policy.Zone || expected["source_image"] != policy.SourceImage || expected["workload_service_account"] != policy.WorkloadServiceAccount || expected["attestation_audience"] != policy.Audience || !validAttemptInstanceName(stringValue(expected["provider_resource_id"]), policy.AllowedInstanceNamePrefix) || expected["verifier_digest"] != verifierDigest {
		return nil, errors.New("attempt does not match the pinned verifier policy or executable")
	}
	jobRequest, ok := expected["request"].(map[string]any)
	if !ok || jobRequest["image_digest"] != policy.Container.ImageDigest || jobRequest["image"] != policy.Container.ImageReference {
		return nil, errors.New("first profile runs only the exact manifest-pinned Cathedral runtime image")
	}
	evidence, ok := document["evidence"].(map[string]any)
	if !ok || !contract.ExactKeys(evidence, "schema", "phase", "attestation_token", "channel_proof", "channel_public_key_base64", "channel_signature_base64") || evidence["schema"] != contract.EvidenceSchema || evidence["phase"] != phase {
		return nil, errors.New("Confidential Space evidence has an invalid exact schema")
	}
	token, ok := evidence["attestation_token"].(string)
	if !ok || len(token) == 0 || len(token) > maxTokenBytes {
		return nil, errors.New("Confidential Space token is invalid or oversized")
	}
	publicKeyRaw, err := decodeBase64(evidence["channel_public_key_base64"], ed25519.PublicKeySize, "channel public key")
	if err != nil || len(publicKeyRaw) != ed25519.PublicKeySize {
		return nil, errors.New("channel public key is not one Ed25519 key")
	}
	signature, err := decodeBase64(evidence["channel_signature_base64"], ed25519.SignatureSize, "channel signature")
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("channel signature is not one Ed25519 signature")
	}
	proof, ok := evidence["channel_proof"].(map[string]any)
	if !ok || !contract.ExactKeys(proof, "schema", "phase", "challenge_sha256", "attestation_token_sha256", "attested_nonces", "ready_assertion", "tls_ekm_sha256") || proof["schema"] != contract.SignedProofSchema || proof["phase"] != phase || proof["challenge_sha256"] != challenge.Digest || proof["attestation_token_sha256"] != contract.Digest([]byte(token)) || proof["tls_ekm_sha256"] != document["tls_ekm_sha256"] {
		return nil, errors.New("channel proof does not bind the challenge, token, and observed TLS EKM")
	}
	proofRaw, _ := contract.CanonicalJSON(proof)
	if !ed25519.Verify(ed25519.PublicKey(publicKeyRaw), append([]byte(contract.ChannelProofDomain), proofRaw...), signature) {
		return nil, errors.New("channel ownership signature is invalid")
	}
	ready, ok := proof["ready_assertion"].(map[string]any)
	if !ok || !contract.ExactKeys(ready, "schema", "phase", "job_context_digest", "nonce_digest", "channel_key_sha256", "channel_binding_sha256", "gpu_count", "gpu_model", "gpu_uuid_sha256", "gpu_ready_state") || ready["schema"] != contract.ReadySchema || ready["phase"] != phase || ready["job_context_digest"] != expected["job_context_digest"] || ready["nonce_digest"] != expected["nonce_digest"] || ready["gpu_count"] != json.Number("1") && ready["gpu_count"] != 1 || ready["gpu_model"] != "NVIDIA H100 80GB" || ready["gpu_ready_state"] != "ready" || !contract.ValidDigest(ready["gpu_uuid_sha256"]) {
		return nil, errors.New("local GPU ReadyState assertion is invalid")
	}
	channelKey := contract.HexDigest(publicKeyRaw)
	channelBinding := contract.ChannelBinding(ed25519.PublicKey(publicKeyRaw), expected)
	if ready["channel_key_sha256"] != channelKey || ready["channel_binding_sha256"] != channelBinding {
		return nil, errors.New("local ReadyState is not bound to the owned attempt channel")
	}
	if phase == "completion" && (expected["channel_key_sha256"] != channelKey || expected["channel_binding_sha256"] != channelBinding) {
		return nil, errors.New("completion channel differs from admission")
	}
	nonces, err := contract.TokenNoncesFromEKMDigest(challenge, document["tls_ekm_sha256"].(string), ready)
	if err != nil || !equalStringArray(proof["attested_nonces"], nonces) {
		return nil, errors.New("channel proof nonce set is invalid")
	}
	verified, err := verifyPKIToken(token, policy, expected, now, nonces)
	if err != nil {
		return nil, err
	}
	identityBytes, _ := contract.CanonicalJSON(verified.gpuIdentitySet)
	identityDigest := contract.HexDigest(identityBytes)
	if phase == "completion" && expected["admission_gpu_identity_set_sha256"] != identityDigest {
		return nil, errors.New("completion GPU identity differs from admission")
	}
	tdxBytes, _ := contract.CanonicalJSON(verified.tdx)
	gpuBytes, _ := contract.CanonicalJSON(verified.nvidia)
	replayInput := map[string]any{
		"schema": "cathedral_confidential_space_replay_bundle_v1", "phase": phase,
		"expected": expected, "evidence": evidence, "tls_ekm_sha256": document["tls_ekm_sha256"],
		"finalize_sha256": document["finalize_sha256"],
	}
	bundleBytes, _ := contract.CanonicalJSON(replayInput)
	verdict := map[string]any{
		"phase": phase, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"evidence_format": expected["evidence_format"], "project_id": expected["project_id"], "zone": expected["zone"],
		"provider_resource_id": expected["provider_resource_id"], "provider_instance_id": expected["provider_instance_id"],
		"source_image": expected["source_image"], "workload_service_account": expected["workload_service_account"], "attestation_audience": expected["attestation_audience"],
		"profile_authority": expected["profile_authority"], "subject_hotkey": expected["subject_hotkey"],
		"worker_id": expected["worker_id"], "job_id": expected["job_id"], "attempt_id": expected["attempt_id"],
		"job_context_digest": expected["job_context_digest"], "nonce_digest": expected["nonce_digest"],
		// This verifier validates the freshness inputs and derives the exact
		// replay values, but it is intentionally stateless.  The durable replay
		// claim is owned by Polaris after this verdict is returned.
		"verifier_digest": verifierDigest, "verified": true, "freshness_verified": true,
		"replay_values_verified": true, "replay_checked": false,
		"cpu_tee": "intel_tdx", "gpu_tee": "nvidia_cc", "same_guest_verified": true,
		"gpu_cc_mode_verified": true, "gpu_ready_state_verified": true, "measurement_policy_verified": true,
		"runtime_isolation_verified": true, "secret_release_authorized": true,
		"channel_key_sha256": channelKey, "channel_binding_sha256": channelBinding, "channel_ownership_verified": true,
		"bundle_sha256": contract.HexDigest(bundleBytes), "cpu_evidence_sha256": contract.HexDigest(tdxBytes),
		"gpu_evidence_sha256": contract.HexDigest(gpuBytes), "gpu_identity_set_sha256": identityDigest,
		"evidence_fingerprint_sha256": contract.HexDigest(append([]byte(fingerprintDomain), bundleBytes...)),
		"evidence_artifacts": map[string]any{
			"bundle": base64.StdEncoding.EncodeToString(bundleBytes), "cpu_evidence": base64.StdEncoding.EncodeToString(tdxBytes),
			"gpu_evidence": base64.StdEncoding.EncodeToString(gpuBytes), "gpu_identity_set": base64.StdEncoding.EncodeToString(identityBytes),
		},
	}
	if phase == "completion" {
		verdict["result_sha256"] = expected["result_sha256"]
		verdict["artifact_manifest_sha256"] = expected["artifact_manifest_sha256"]
		verdict["kbs_release_ack_sha256"] = expected["kbs_release_ack_sha256"]
	}
	return verdict, nil
}

func verifyPKIToken(token string, policy *verifierPolicy, expected map[string]any, now time.Time, expectedNonces []string) (*verifiedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("attestation token is not a compact JWT")
	}
	headerRaw, err := decodeBase64URL(parts[0], 256*1024, "JWT header")
	if err != nil {
		return nil, err
	}
	payloadRaw, err := decodeBase64URL(parts[1], maxTokenBytes, "JWT payload")
	if err != nil {
		return nil, err
	}
	signature, err := decodeBase64URL(parts[2], 64*1024, "JWT signature")
	if err != nil {
		return nil, err
	}
	headerValue, err := contract.StrictJSON(headerRaw)
	if err != nil {
		return nil, errors.New("JWT header is not strict JSON")
	}
	header, ok := headerValue.(map[string]any)
	if !ok || header["alg"] != "RS256" {
		return nil, errors.New("PKI token must use RS256")
	}
	for key := range header {
		if key != "alg" && key != "typ" && key != "x5c" {
			return nil, errors.New("PKI token header contains an unsupported field")
		}
	}
	chainValues, ok := header["x5c"].([]any)
	if !ok || len(chainValues) != 3 {
		return nil, errors.New("PKI token must carry the documented three-certificate chain")
	}
	certificates := make([]*x509.Certificate, 3)
	for index, raw := range chainValues {
		certificateDER, err := decodeBase64(raw, 128*1024, "x5c certificate")
		if err != nil {
			return nil, err
		}
		certificates[index], err = x509.ParseCertificate(certificateDER)
		if err != nil {
			return nil, errors.New("x5c certificate is invalid")
		}
	}
	if !certificates[2].Equal(policy.ConfidentialSpaceRootCert) {
		return nil, errors.New("PKI token root differs from the stored Google Attestation root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(policy.ConfidentialSpaceRootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certificates[1])
	if _, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, errors.New("Google Attestation PKI certificate chain is invalid")
	}
	publicKey, ok := certificates[0].PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 2048 {
		return nil, errors.New("PKI token leaf does not use an acceptable RSA key")
	}
	signed := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("PKI token signature is invalid")
	}
	claimsValue, err := contract.StrictJSON(payloadRaw)
	if err != nil {
		return nil, errors.New("PKI token claims are not strict JSON")
	}
	claims, ok := claimsValue.(map[string]any)
	if !ok {
		return nil, errors.New("PKI token claims must be an object")
	}
	if err := validateTopClaims(claims, policy, expected, now, expectedNonces); err != nil {
		return nil, err
	}
	submods := claims["submods"].(map[string]any)
	tdx := claims["tdx"].([]any)[0].(map[string]any)
	nvidia := submods["nvidia_gpu"].(map[string]any)
	gpu := nvidia["gpus"].([]any)[0].(map[string]any)
	identitySet := map[string]any{"schema": gpuIdentitySetSchema, "gpus": []any{map[string]any{
		"hwmodel": gpu["hwmodel"], "ueid": gpu["ueid"], "driver_version": gpu["driver_version"],
		"vbios_version": gpu["vbios_version"], "l4_serial_number": gpu["l4_serial_number"],
	}}}
	return &verifiedToken{raw: token, claims: claims, tdx: tdx, nvidia: nvidia, gpuIdentitySet: identitySet}, nil
}

func validateTopClaims(claims map[string]any, policy *verifierPolicy, expected map[string]any, now time.Time, expectedNonces []string) error {
	if claims["iss"] != issuer || claims["aud"] != policy.Audience || claims["hwmodel"] != "GCP_INTEL_TDX" || claims["oemid"] != json.Number("11129") && claims["oemid"] != float64(11129) || claims["secboot"] != true || claims["dbgstat"] != "disabled-since-boot" || claims["swname"] != "CONFIDENTIAL_SPACE" {
		return errors.New("Confidential Space token identity, production, or secure-boot claims are invalid")
	}
	attesterTCB, ok := claims["attester_tcb"].([]any)
	if !ok || len(attesterTCB) != 1 || attesterTCB[0] != "INTEL" {
		return errors.New("Confidential Space token is not rooted in Intel TDX evidence")
	}
	serviceAccounts, ok := claims["google_service_accounts"].([]any)
	if !ok || len(serviceAccounts) != 1 || serviceAccounts[0] != policy.WorkloadServiceAccount {
		return errors.New("Confidential Space workload service account is not policy allowed")
	}
	issued, err := unixClaim(claims["iat"], "iat")
	if err != nil {
		return err
	}
	notBefore, err := unixClaim(claims["nbf"], "nbf")
	if err != nil {
		return err
	}
	expires, err := unixClaim(claims["exp"], "exp")
	if err != nil {
		return err
	}
	skew := time.Duration(policy.MaxClockSkewSeconds) * time.Second
	if issued.After(now.Add(skew)) || now.Before(notBefore.Add(-skew)) || !now.Before(expires) || now.Sub(issued) > time.Duration(policy.MaxTokenAgeSeconds)*time.Second+skew || expires.Sub(issued) > time.Duration(policy.MaxTokenAgeSeconds)*time.Second+skew {
		return errors.New("Confidential Space token is stale, premature, expired, or overlong")
	}
	if !equalStringArray(claims["eat_nonce"], expectedNonces) {
		return errors.New("Confidential Space token nonce set is stale or mismatched")
	}
	swversions, ok := claims["swversion"].([]any)
	if !ok || len(swversions) != 1 {
		return errors.New("Confidential Space software version claim is invalid")
	}
	swversion, _ := swversions[0].(string)
	if !containsString(policy.AllowedSWVersions, swversion) {
		return errors.New("Confidential Space image version is not policy allowed")
	}
	tdxValues, ok := claims["tdx"].([]any)
	if !ok || len(tdxValues) != 1 {
		return errors.New("Confidential Space token must carry one TDX claim set")
	}
	tdx, ok := tdxValues[0].(map[string]any)
	if !ok || !contract.ExactKeys(tdx, "gcp_attester_tcb_status", "gcp_attester_tcb_date") || !containsString(policy.AllowedTDXTCBStatuses, stringValue(tdx["gcp_attester_tcb_status"])) {
		return errors.New("TDX TCB status is not policy allowed")
	}
	minimum, err := time.Parse(time.RFC3339, policy.MinimumTDXTCBDate)
	if err != nil {
		return errors.New("policy minimum TDX TCB date is invalid")
	}
	observed, err := time.Parse(time.RFC3339, stringValue(tdx["gcp_attester_tcb_date"]))
	if err != nil || observed.Before(minimum) {
		return errors.New("TDX TCB date is older than policy")
	}
	submods, ok := claims["submods"].(map[string]any)
	if !ok {
		return errors.New("Confidential Space token submods are invalid")
	}
	return validateSubmods(claims, submods, policy, expected)
}

func validateSubmods(claims, submods map[string]any, policy *verifierPolicy, expected map[string]any) error {
	space, ok := submods["confidential_space"].(map[string]any)
	if !ok {
		return errors.New("Confidential Space support attributes are absent")
	}
	attributes, ok := space["support_attributes"].([]any)
	if !ok || !containsAny(attributes, "STABLE") {
		return errors.New("Confidential Space image is not in STABLE support")
	}
	monitoring, ok := space["monitoring_enabled"].(map[string]any)
	if !ok || monitoring["memory"] != false {
		return errors.New("Confidential Space memory monitoring must be disabled")
	}
	container, ok := submods["container"].(map[string]any)
	if !ok || container["image_digest"] != policy.Container.ImageDigest || container["image_reference"] != policy.Container.ImageReference || container["restart_policy"] != policy.Container.RestartPolicy || !canonicalEqual(container["args"], stringsToAny(policy.Container.Args)) || !canonicalEqual(container["env"], policy.Container.Environment) || !emptyArray(container["cmd_override"]) || !emptyMap(container["env_override"]) {
		return errors.New("attested workload container image, args, env, or restart policy differs from policy")
	}
	gce, ok := submods["gce"].(map[string]any)
	if !ok || gce["project_id"] != policy.ProjectID || gce["zone"] != policy.Zone || gce["instance_name"] != expected["provider_resource_id"] || gce["instance_id"] != expected["provider_instance_id"] || !validAttemptInstanceName(stringValue(gce["instance_name"]), policy.AllowedInstanceNamePrefix) {
		return errors.New("attested GCE project, zone, or instance is not policy allowed")
	}
	expectedSubject := "https://www.googleapis.com/compute/v1/projects/" + policy.ProjectID + "/zones/" + policy.Zone + "/instances/" + stringValue(gce["instance_id"])
	if claims["sub"] != expectedSubject {
		return errors.New("attested subject does not bind the exact GCE instance")
	}
	nvidia, ok := submods["nvidia_gpu"].(map[string]any)
	if !ok || !contract.ExactKeys(nvidia, "cc_feature", "cc_mode", "gpus") || nvidia["cc_feature"] != "SPT" || nvidia["cc_mode"] != "ON" {
		return errors.New("NVIDIA token claim is not SPT CC mode ON")
	}
	gpus, ok := nvidia["gpus"].([]any)
	if !ok || len(gpus) != 1 {
		return errors.New("token must attest exactly one NVIDIA GPU")
	}
	gpu, ok := gpus[0].(map[string]any)
	if !ok || !contract.ExactKeys(gpu, "driver_version", "hwmodel", "l4_serial_number", "ueid", "vbios_version") || gpu["hwmodel"] != "GCP_NVIDIA_H100" || !containsString(policy.AllowedNVIDIADrivers, stringValue(gpu["driver_version"])) || !containsString(policy.AllowedNVIDIAVBIOS, stringValue(gpu["vbios_version"])) || stringValue(gpu["ueid"]) == "" || stringValue(gpu["l4_serial_number"]) == "" {
		return errors.New("attested H100 identity, driver, or VBIOS is not policy allowed")
	}
	return nil
}

func validAttemptInstanceName(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) <= len(prefix) || len(value) > 63 {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return value[len(value)-1] != '-'
}

func decodeBase64URL(value string, maximum int, label string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not bounded canonical base64url", label)
	}
	return decoded, nil
}

func decodeBase64(value any, maximum int, label string) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%s is not a string", label)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, fmt.Errorf("%s is not bounded canonical base64", label)
	}
	return decoded, nil
}

func unixClaim(value any, label string) (time.Time, error) {
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, fmt.Errorf("token %s is not an integer", label)
	}
	seconds, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("token %s is invalid", label)
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func equalStringArray(value any, expected []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for index, item := range items {
		if item != expected[index] {
			return false
		}
	}
	return true
}

func containsAny(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contract.CanonicalJSON(left)
	rightRaw, rightErr := contract.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func emptyArray(value any) bool    { items, ok := value.([]any); return ok && len(items) == 0 }
func emptyMap(value any) bool      { items, ok := value.(map[string]any); return ok && len(items) == 0 }
func stringValue(value any) string { text, _ := value.(string); return text }
func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
