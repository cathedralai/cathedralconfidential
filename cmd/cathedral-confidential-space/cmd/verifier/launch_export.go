package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

var launchReceiptKeys = []string{
	"schema", "receipt_id", "execution_class", "profile_id", "provider", "machine_type", "zone", "cpu_tee", "gpu_model", "gpu_count", "provisioning_model",
	"worker_id", "subject_hotkey", "job_id", "attempt_id", "profile_authority", "job_context_digest",
	"admission_bundle_digest", "admission_nonce_digest", "admission_cpu_evidence_digest", "admission_gpu_evidence_digest", "admission_gpu_identity_set_digest",
	"completion_bundle_digest", "completion_nonce_digest", "completion_cpu_evidence_digest", "completion_gpu_evidence_digest", "completion_gpu_identity_set_digest",
	"channel_binding_digest", "image_digest", "policy_digest", "input_digest", "model_digest", "result_digest", "artifact_manifest_digest", "secret_release_grant_digest",
	"outcome", "deletion_confirmed", "deletion_evidence_digest", "policy_registry_release", "policy_registry_digest", "issued_at", "signing_key_id", "signature",
}

func verifyLaunchExport(raw []byte, policy *verifierPolicy, now time.Time, verifierDigest string) (map[string]any, error) {
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "schema", "admission", "completion", "release_control", "deletion_observation", "receipt") || document["schema"] != "cathedral_cc_gpu_launch_export_v1" {
		return nil, errors.New("launch export has an invalid exact schema")
	}
	admission, admissionOK := document["admission"].(map[string]any)
	completion, completionOK := document["completion"].(map[string]any)
	release, releaseOK := document["release_control"].(map[string]any)
	deletion, deletionOK := document["deletion_observation"].(map[string]any)
	receipt, receiptOK := document["receipt"].(map[string]any)
	if !admissionOK || !completionOK || !releaseOK || !deletionOK || !receiptOK || !contract.ExactKeys(admission, "expected", "evidence", "tls_ekm_sha256", "finalize_sha256") || !contract.ExactKeys(completion, "expected", "evidence", "tls_ekm_sha256", "finalize_sha256") {
		return nil, errors.New("launch export artifacts have invalid exact schemas")
	}
	admissionRaw, _ := contract.CanonicalJSON(admission)
	completionRaw, _ := contract.CanonicalJSON(completion)
	admissionVerdict, err := verifyInput(admissionRaw, "admission", policy, now, verifierDigest)
	if err != nil {
		return nil, err
	}
	completionVerdict, err := verifyInput(completionRaw, "completion", policy, now, verifierDigest)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"profile_id", "subject_hotkey", "worker_id", "job_id", "attempt_id", "job_context_digest", "channel_key_sha256", "channel_binding_sha256", "gpu_identity_set_sha256"} {
		if admissionVerdict[key] != completionVerdict[key] {
			return nil, errors.New("launch admission and completion differ on same-attempt binding")
		}
	}
	if !validLaunchReceiptExact(receipt, admissionVerdict, completionVerdict, admission["expected"].(map[string]any)) {
		return nil, errors.New("launch receipt does not bind the re-verified attempt result")
	}
	if err := verifySignedArtifact(receipt, policy.TrustedReceiptKeys); err != nil {
		return nil, err
	}
	admissionArtifacts := admissionVerdict["evidence_artifacts"].(map[string]any)
	completionArtifacts := completionVerdict["evidence_artifacts"].(map[string]any)
	admissionBundle, err := base64.StdEncoding.Strict().DecodeString(admissionArtifacts["bundle"].(string))
	if err != nil || receipt["admission_bundle_digest"] != contract.Digest(admissionBundle) {
		return nil, errors.New("launch receipt admission bundle digest is mismatched")
	}
	completionBundle, err := base64.StdEncoding.Strict().DecodeString(completionArtifacts["bundle"].(string))
	if err != nil || receipt["completion_bundle_digest"] != contract.Digest(completionBundle) {
		return nil, errors.New("launch receipt completion bundle digest is mismatched")
	}
	releaseRaw, _ := contract.CanonicalJSON(release)
	deletionRaw, _ := contract.CanonicalJSON(deletion)
	if receipt["secret_release_grant_digest"] != contract.Digest(releaseRaw) || receipt["deletion_evidence_digest"] != contract.Digest(deletionRaw) {
		return nil, errors.New("launch receipt release or deletion artifact digest is mismatched")
	}
	if err := verifyReleaseGrant(releaseRaw, receipt, admission["expected"].(map[string]any), admission["evidence"].(map[string]any), admission["tls_ekm_sha256"].(string), policy, now); err != nil {
		return nil, err
	}
	if err := verifyDeletion(deletionRaw, receipt, completion["expected"].(map[string]any), policy, now); err != nil {
		return nil, err
	}
	releaseAck := release["release_ack"].(map[string]any)
	releaseAckRaw, _ := contract.CanonicalJSON(releaseAck)
	completionExpected := completion["expected"].(map[string]any)
	if completionExpected["admission_bundle_sha256"] != admissionVerdict["bundle_sha256"] || completionExpected["admission_gpu_identity_set_sha256"] != admissionVerdict["gpu_identity_set_sha256"] || completionExpected["kbs_release_ack_sha256"] != contract.HexDigest(releaseAckRaw) {
		return nil, errors.New("completion challenge does not bind the re-verified admission and exact KBS release ack")
	}
	status := "PASS"
	reason := "verified"
	runtimeIsolation := admissionVerdict["runtime_isolation_verified"] == true && completionVerdict["runtime_isolation_verified"] == true
	if !runtimeIsolation {
		status = "FAIL"
		reason = "first-party runtime network, mount, privilege, and cgroup isolation is not verified"
	}
	return map[string]any{
		"schema": "cathedral_cc_gpu_launch_export_verdict_v1", "status": status, "reason": reason,
		"profile_id": contract.ProfileID, "job_id": receipt["job_id"], "attempt_id": receipt["attempt_id"], "job_context_digest": receipt["job_context_digest"],
		"receipt_digest": contract.Digest(mustCanonical(receipt)), "receipt_signature_verified": true,
		"admission_bundle_digest": contract.Digest(admissionBundle), "completion_bundle_digest": contract.Digest(completionBundle),
		"secret_release_grant_digest": contract.Digest(releaseRaw), "deletion_evidence_digest": contract.Digest(deletionRaw),
		"result_digest": receipt["result_digest"], "artifact_manifest_digest": receipt["artifact_manifest_digest"], "channel_binding_digest": receipt["channel_binding_digest"],
		"kbs_config_sha256": releaseAck["kbs_config_sha256"], "verifier_digest": verifierDigest,
		"runtime_isolation_verified": runtimeIsolation, "live_hardware_round_trip_verified": true,
		"release_request_sha256": release["release_request_sha256"], "one_time_release_verified": true,
	}, nil
}

func validLaunchReceiptExact(receipt, admission, completion, expected map[string]any) bool {
	if !contract.ExactKeys(receipt, launchReceiptKeys...) || receipt["schema"] != "cathedral_cc_gpu_job_receipt_v1" || receipt["execution_class"] != "cc_gpu" || receipt["profile_id"] != contract.ProfileID || receipt["provider"] != "gcp" || receipt["machine_type"] != "a3-highgpu-1g" || receipt["zone"] != "us-central1-a" || receipt["cpu_tee"] != "intel_tdx" || receipt["gpu_model"] != "nvidia_h100_80gb" || receipt["provisioning_model"] != "spot" || receipt["gpu_count"] != 1 && receipt["gpu_count"] != expected["gpu_count"] || receipt["outcome"] != "completed" || receipt["deletion_confirmed"] != true {
		return false
	}
	receiptID, receiptIDOK := receipt["receipt_id"].(string)
	if !receiptIDOK || !strings.HasPrefix(receiptID, "cc-gpu-receipt-sha256:") || !contract.ValidDigest(strings.TrimPrefix(receiptID, "cc-gpu-receipt-")) {
		return false
	}
	for _, key := range []string{"worker_id", "subject_hotkey", "job_id", "attempt_id", "profile_authority", "job_context_digest"} {
		if receipt[key] != admission[key] || receipt[key] != completion[key] {
			return false
		}
	}
	if receipt["admission_nonce_digest"] != admission["nonce_digest"] || receipt["completion_nonce_digest"] != completion["nonce_digest"] || receipt["channel_binding_digest"] != "sha256:"+admission["channel_binding_sha256"].(string) || receipt["admission_cpu_evidence_digest"] != "sha256:"+admission["cpu_evidence_sha256"].(string) || receipt["admission_gpu_evidence_digest"] != "sha256:"+admission["gpu_evidence_sha256"].(string) || receipt["admission_gpu_identity_set_digest"] != "sha256:"+admission["gpu_identity_set_sha256"].(string) || receipt["completion_cpu_evidence_digest"] != "sha256:"+completion["cpu_evidence_sha256"].(string) || receipt["completion_gpu_evidence_digest"] != "sha256:"+completion["gpu_evidence_sha256"].(string) || receipt["completion_gpu_identity_set_digest"] != "sha256:"+completion["gpu_identity_set_sha256"].(string) || receipt["result_digest"] != "sha256:"+completion["result_sha256"].(string) || receipt["artifact_manifest_digest"] != "sha256:"+completion["artifact_manifest_sha256"].(string) || receipt["image_digest"] != expected["request"].(map[string]any)["image_digest"] {
		return false
	}
	request, requestOK := expected["request"].(map[string]any)
	inputs, inputsOK := request["protected_inputs"].([]any)
	if !requestOK || !inputsOK || len(inputs) != 2 {
		return false
	}
	input, inputOK := inputs[0].(map[string]any)
	model, modelOK := inputs[1].(map[string]any)
	policyRaw, policyErr := contract.CanonicalJSON(request["policy"])
	if !inputOK || !modelOK || input["kind"] != "input" || model["kind"] != "model" || receipt["input_digest"] != input["plaintext_digest_sha256"] || receipt["model_digest"] != model["plaintext_digest_sha256"] || policyErr != nil || receipt["policy_digest"] != contract.Digest(policyRaw) {
		return false
	}
	for _, key := range []string{"policy_digest", "input_digest", "model_digest", "policy_registry_digest", "admission_bundle_digest", "completion_bundle_digest", "secret_release_grant_digest", "deletion_evidence_digest"} {
		if !contract.ValidDigest(receipt[key]) {
			return false
		}
	}
	_, timeErr := parseCanonicalTime(receipt["issued_at"])
	return timeErr == nil
}

func mustCanonical(value any) []byte { raw, _ := contract.CanonicalJSON(value); return raw }
