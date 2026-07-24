package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func verifyReleaseGrant(raw []byte, receipt, expected, evidence map[string]any, tlsEKMSHA256 string, policy *verifierPolicy, now time.Time) error {
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return errors.New("release control artifact is not strict JSON")
	}
	control, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(control, "schema", "job_id", "attempt_id", "job_context_digest", "release_request", "release_request_sha256", "release_ack", "release_ack_sha256", "release_policy", "release_policy_sha256", "published_at") || control["schema"] != "cathedral_cc_gpu_release_control_v1" || control["job_id"] != receipt["job_id"] || control["attempt_id"] != receipt["attempt_id"] || control["job_context_digest"] != receipt["job_context_digest"] {
		return errors.New("release control artifact has an invalid exact schema or job binding")
	}
	releasePolicy, policyOK := control["release_policy"].(map[string]any)
	releasePolicyRaw, _ := contract.CanonicalJSON(releasePolicy)
	validatedPolicy, policyErr := contract.ValidateReleasePolicy(releasePolicyRaw, expected, now)
	if !policyOK || policyErr != nil || control["release_policy_sha256"] != contract.Digest(releasePolicyRaw) || verifySignedArtifact(validatedPolicy, policy.TrustedKBSKeys) != nil {
		return errors.New("release policy is stale, semantically mismatched, or untrusted")
	}
	request, requestOK := control["release_request"].(map[string]any)
	document, ok := control["release_ack"].(map[string]any)
	proof, proofOK := evidence["channel_proof"].(map[string]any)
	var ready map[string]any
	readyOK := false
	if proofOK {
		ready, readyOK = proof["ready_assertion"].(map[string]any)
	}
	if !requestOK || !contract.ExactKeys(request, "schema", "job_id", "attempt_id", "job_context_digest", "protected_input_set_digest", "one_time_nonce_digest") || request["schema"] != "cathedral_cc_gpu_kbs_release_request_v1" || request["job_id"] != receipt["job_id"] || request["attempt_id"] != receipt["attempt_id"] || request["job_context_digest"] != receipt["job_context_digest"] || request["protected_input_set_digest"] != expected["request"].(map[string]any)["protected_input_set_digest"] || !contract.ValidDigest(request["one_time_nonce_digest"]) || control["release_request_sha256"] != digestCanonical(request) {
		return errors.New("release control one-time request is invalid or mismatched")
	}
	if !ok || !contract.ExactKeys(document,
		"schema", "grant_id", "job_id", "attempt_id", "job_context_digest", "channel_key_sha256",
		"channel_binding_sha256", "protected_input_set_digest", "admission_evidence_sha256", "admission_token_sha256", "tls_ekm_sha256",
		"one_time_nonce_digest", "grant_artifact_sha256", "release_request_sha256", "kbs_config_sha256", "issued_at", "expires_at", "single_use",
		"consumed_at", "signing_key_id", "signature",
	) || !proofOK || !readyOK || document["schema"] != "cathedral_cc_gpu_kbs_release_ack_v1" || document["kbs_config_sha256"] != policy.TrustedKBSConfigSHA256 || document["job_id"] != receipt["job_id"] || document["attempt_id"] != receipt["attempt_id"] || document["job_context_digest"] != receipt["job_context_digest"] || document["channel_key_sha256"] != ready["channel_key_sha256"] || document["channel_binding_sha256"] != strings.TrimPrefix(receipt["channel_binding_digest"].(string), "sha256:") || document["protected_input_set_digest"] != expected["request"].(map[string]any)["protected_input_set_digest"] || document["admission_evidence_sha256"] != digestCanonical(evidence) || document["admission_token_sha256"] != contract.Digest([]byte(evidence["attestation_token"].(string))) || document["tls_ekm_sha256"] != tlsEKMSHA256 || document["one_time_nonce_digest"] != request["one_time_nonce_digest"] || document["release_request_sha256"] != control["release_request_sha256"] || document["single_use"] != true || document["grant_artifact_sha256"] != control["release_policy_sha256"] || control["release_ack_sha256"] != digestCanonical(document) {
		return errors.New("release grant one-time semantics or job/channel binding is invalid")
	}
	if _, err := parseCanonicalTime(control["published_at"]); err != nil {
		return err
	}
	issued, err := parseCanonicalTime(document["issued_at"])
	if err != nil {
		return err
	}
	expires, err := parseCanonicalTime(document["expires_at"])
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute {
		return errors.New("release grant lifetime is invalid")
	}
	consumed, err := parseCanonicalTime(document["consumed_at"])
	receiptAt, receiptErr := parseCanonicalTime(receipt["issued_at"])
	publishedAt, publishedErr := parseCanonicalTime(control["published_at"])
	skew := time.Duration(policy.MaxClockSkewSeconds) * time.Second
	if err != nil || receiptErr != nil || publishedErr != nil || consumed.Before(issued) || consumed.After(expires) || publishedAt.Before(consumed.Add(-skew)) || publishedAt.After(receiptAt.Add(skew)) || receiptAt.Before(consumed.Add(-skew)) || receiptAt.After(consumed.Add(time.Duration(policy.MaxReleaseToReceiptSeconds)*time.Second)) || now.Before(receiptAt.Add(-skew)) {
		return errors.New("release grant was not consumed once within its lifetime")
	}
	return verifySignedArtifact(document, policy.TrustedKBSKeys)
}

func digestCanonical(value any) string {
	raw, _ := contract.CanonicalJSON(value)
	return contract.Digest(raw)
}

func verifyReleaseInput(raw []byte, policy *verifierPolicy, now time.Time, verifierDigest string) (map[string]any, error) {
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return nil, errors.New("release verifier input is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document, "expected", "evidence", "tls_ekm_sha256", "finalize_sha256", "release_request", "release_ack") || document["finalize_sha256"] != nil {
		return nil, errors.New("release verifier input has an invalid exact schema")
	}
	expected, expectedOK := document["expected"].(map[string]any)
	if !expectedOK {
		return nil, errors.New("release verifier expected contract is invalid")
	}
	admissionExpected := make(map[string]any, len(expected))
	for key, value := range expected {
		admissionExpected[key] = value
	}
	admissionExpected["phase"] = "admission"
	admissionExpected["nonce_digest"] = admissionExpected["admission_nonce_digest"]
	admissionExpected["channel_key_sha256"] = nil
	admissionExpected["channel_binding_sha256"] = nil
	base, _ := contract.CanonicalJSON(map[string]any{
		"expected": admissionExpected, "evidence": document["evidence"],
		"tls_ekm_sha256": document["tls_ekm_sha256"], "finalize_sha256": nil,
	})
	admissionVerdict, err := verifyInput(base, "admission", policy, now, verifierDigest)
	if err != nil {
		return nil, err
	}
	evidence := document["evidence"].(map[string]any)
	evidenceRaw, _ := contract.CanonicalJSON(evidence)
	proof := evidence["channel_proof"].(map[string]any)
	ready := proof["ready_assertion"].(map[string]any)
	ack, ok := document["release_ack"].(map[string]any)
	releaseRequest, requestOK := document["release_request"].(map[string]any)
	if !requestOK || !contract.ExactKeys(releaseRequest, "schema", "job_id", "attempt_id", "job_context_digest", "protected_input_set_digest", "one_time_nonce_digest") || releaseRequest["schema"] != "cathedral_cc_gpu_kbs_release_request_v1" || releaseRequest["job_id"] != expected["job_id"] || releaseRequest["attempt_id"] != expected["attempt_id"] || releaseRequest["job_context_digest"] != expected["job_context_digest"] || releaseRequest["protected_input_set_digest"] != expected["request"].(map[string]any)["protected_input_set_digest"] || !contract.ValidDigest(releaseRequest["one_time_nonce_digest"]) {
		return nil, errors.New("release verifier input does not carry the exact canonical one-time request")
	}
	if !ok || !contract.ExactKeys(ack,
		"schema", "grant_id", "job_id", "attempt_id", "job_context_digest", "channel_key_sha256",
		"channel_binding_sha256", "protected_input_set_digest", "admission_evidence_sha256",
		"admission_token_sha256", "tls_ekm_sha256", "one_time_nonce_digest", "grant_artifact_sha256", "release_request_sha256", "kbs_config_sha256",
		"issued_at", "expires_at", "single_use", "consumed_at", "signing_key_id", "signature",
	) || ack["schema"] != "cathedral_cc_gpu_kbs_release_ack_v1" || ack["kbs_config_sha256"] != policy.TrustedKBSConfigSHA256 || ack["job_id"] != expected["job_id"] || ack["attempt_id"] != expected["attempt_id"] || ack["job_context_digest"] != expected["job_context_digest"] || ack["channel_key_sha256"] != ready["channel_key_sha256"] || ack["channel_binding_sha256"] != ready["channel_binding_sha256"] || ack["protected_input_set_digest"] != expected["request"].(map[string]any)["protected_input_set_digest"] || ack["admission_evidence_sha256"] != contract.Digest(evidenceRaw) || ack["admission_token_sha256"] != contract.Digest([]byte(evidence["attestation_token"].(string))) || ack["tls_ekm_sha256"] != document["tls_ekm_sha256"] || ack["one_time_nonce_digest"] != releaseRequest["one_time_nonce_digest"] || ack["release_request_sha256"] != digestCanonical(releaseRequest) || !contract.ValidDigest(ack["grant_artifact_sha256"]) || ack["single_use"] != true {
		return nil, errors.New("signed KBS release ack does not bind the verified admission and one-time grant")
	}
	issued, err := parseCanonicalTime(ack["issued_at"])
	if err != nil {
		return nil, err
	}
	expires, err := parseCanonicalTime(ack["expires_at"])
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute || now.Before(issued.Add(-30*time.Second)) || now.After(expires.Add(30*time.Second)) {
		return nil, errors.New("signed KBS release ack is stale or overlong")
	}
	consumed, err := parseCanonicalTime(ack["consumed_at"])
	if err != nil || consumed.Before(issued) || consumed.After(expires) {
		return nil, errors.New("signed KBS release ack was not consumed once within its lifetime")
	}
	if err := verifySignedArtifact(ack, policy.TrustedKBSKeys); err != nil {
		return nil, err
	}
	ackRaw, _ := contract.CanonicalJSON(ack)
	return map[string]any{
		"phase": "release", "execution_class": "cc_gpu", "evidence_format": expected["evidence_format"],
		"profile_id": expected["profile_id"], "profile_authority": expected["profile_authority"],
		"subject_hotkey": expected["subject_hotkey"], "worker_id": expected["worker_id"], "job_id": expected["job_id"],
		"attempt_id": expected["attempt_id"], "job_context_digest": expected["job_context_digest"],
		"project_id": expected["project_id"], "zone": expected["zone"], "provider_resource_id": expected["provider_resource_id"],
		"provider_instance_id": expected["provider_instance_id"], "source_image": expected["source_image"],
		"workload_service_account": expected["workload_service_account"], "attestation_audience": expected["attestation_audience"],
		"verifier_digest": verifierDigest, "verified": true, "kbs_ack_signature_verified": true,
		"same_tls_ekm_verified": true, "single_use_consumed_verified": true, "independent_admission_verification": true,
		"channel_binding_sha256": ready["channel_binding_sha256"], "admission_bundle_sha256": admissionVerdict["bundle_sha256"],
		"admission_token_sha256": ack["admission_token_sha256"], "tls_ekm_sha256": document["tls_ekm_sha256"],
		"kbs_release_ack_sha256": contract.Digest(ackRaw),
		"release_request_sha256": digestCanonical(releaseRequest), "one_time_nonce_digest": releaseRequest["one_time_nonce_digest"],
		"kbs_config_sha256": ack["kbs_config_sha256"],
	}, nil
}

func verifyDeletion(raw []byte, receipt, expected map[string]any, policy *verifierPolicy, now time.Time) error {
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return errors.New("deletion evidence is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document,
		"schema", "job_id", "attempt_id", "job_context_digest", "channel_binding_sha256",
		"provider", "project_id", "zone", "provider_resource_id", "provider_instance_id", "state", "deleted_at", "signing_key_id", "signature",
	) || document["schema"] != "cathedral_cc_gpu_deletion_observation_v1" || document["job_id"] != receipt["job_id"] || document["attempt_id"] != receipt["attempt_id"] || document["job_context_digest"] != receipt["job_context_digest"] || document["channel_binding_sha256"] != receipt["channel_binding_digest"] || document["provider"] != "gcp" || document["project_id"] != policy.ProjectID || document["zone"] != policy.Zone || document["provider_resource_id"] != expected["provider_resource_id"] || document["provider_instance_id"] != expected["provider_instance_id"] || document["state"] != "deleted" {
		return errors.New("deletion observation does not confirm the exact GCP attempt is deleted")
	}
	deletedAt, err := parseCanonicalTime(document["deleted_at"])
	if err != nil {
		return err
	}
	receiptAt, err := parseCanonicalTime(receipt["issued_at"])
	skew := time.Duration(policy.MaxClockSkewSeconds) * time.Second
	if err != nil || deletedAt.After(receiptAt.Add(skew)) || receiptAt.After(deletedAt.Add(time.Duration(policy.MaxDeletionAgeSeconds)*time.Second)) || now.Before(receiptAt.Add(-skew)) || now.After(receiptAt.Add(time.Duration(policy.MaxDeletionAgeSeconds)*time.Second)) {
		return errors.New("deletion observation is stale, future-dated, or predates receipt completion")
	}
	return verifySignedArtifact(document, policy.TrustedDeletionKeys)
}

func verifySignedArtifact(document map[string]any, trusted map[string]string) error {
	keyID, ok := document["signing_key_id"].(string)
	encodedKey, exists := trusted[keyID]
	if !ok || !exists {
		return errors.New("signed artifact key is not trusted")
	}
	signatureObject, ok := document["signature"].(map[string]any)
	if !ok || !contract.ExactKeys(signatureObject, "algorithm", "value_base64") || signatureObject["algorithm"] != "ed25519" {
		return errors.New("signed artifact signature schema is invalid")
	}
	publicKey, _ := base64.StdEncoding.Strict().DecodeString(encodedKey)
	signature, err := decodeBase64(signatureObject["value_base64"], ed25519.SignatureSize, "artifact signature")
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("signed artifact signature is invalid")
	}
	unsigned := make(map[string]any, len(document)-1)
	for key, value := range document {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return errors.New("signed artifact signature verification failed")
	}
	return nil
}

func parseCanonicalTime(value any) (time.Time, error) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, errors.New("artifact time is invalid")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000Z", text)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000000Z") != text {
		return time.Time{}, fmt.Errorf("artifact time %q is not canonical UTC", text)
	}
	return parsed, nil
}
