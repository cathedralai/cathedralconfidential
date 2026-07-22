package main

import (
	"testing"
	"time"
)

func launchReceiptFixture(t *testing.T) (map[string]any, map[string]any, map[string]any, map[string]any) {
	t.Helper()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	pki := makePKI(t, now)
	policy := testPolicy(pki)
	expected := testExpected(t, policy, "admission", "", "")
	admission := map[string]any{
		"profile_id": expected["profile_id"], "subject_hotkey": expected["subject_hotkey"], "worker_id": expected["worker_id"],
		"job_id": expected["job_id"], "attempt_id": expected["attempt_id"], "job_context_digest": expected["job_context_digest"],
		"profile_authority": expected["profile_authority"], "nonce_digest": expected["nonce_digest"],
		"channel_binding_sha256": repeat("1"), "cpu_evidence_sha256": repeat("2"), "gpu_evidence_sha256": repeat("3"), "gpu_identity_set_sha256": repeat("4"),
	}
	completion := map[string]any{}
	for key, value := range admission {
		completion[key] = value
	}
	completion["nonce_digest"] = "sha256:" + repeat("5")
	completion["cpu_evidence_sha256"] = repeat("6")
	completion["gpu_evidence_sha256"] = repeat("7")
	completion["gpu_identity_set_sha256"] = repeat("4")
	completion["result_sha256"] = repeat("8")
	completion["artifact_manifest_sha256"] = repeat("9")
	request := expected["request"].(map[string]any)
	inputs := request["protected_inputs"].([]any)
	receipt := map[string]any{
		"schema": "cathedral_cc_gpu_job_receipt_v1", "receipt_id": "cc-gpu-receipt-sha256:" + repeat("a"),
		"execution_class": "cc_gpu", "profile_id": expected["profile_id"], "provider": "gcp", "machine_type": "a3-highgpu-1g", "zone": "us-central1-a",
		"cpu_tee": "intel_tdx", "gpu_model": "nvidia_h100_80gb", "gpu_count": 1, "provisioning_model": "spot",
		"worker_id": expected["worker_id"], "subject_hotkey": expected["subject_hotkey"], "job_id": expected["job_id"], "attempt_id": expected["attempt_id"],
		"profile_authority": expected["profile_authority"], "job_context_digest": expected["job_context_digest"],
		"admission_bundle_digest": "sha256:" + repeat("b"), "admission_nonce_digest": admission["nonce_digest"],
		"admission_cpu_evidence_digest": "sha256:" + repeat("2"), "admission_gpu_evidence_digest": "sha256:" + repeat("3"), "admission_gpu_identity_set_digest": "sha256:" + repeat("4"),
		"completion_bundle_digest": "sha256:" + repeat("c"), "completion_nonce_digest": completion["nonce_digest"],
		"completion_cpu_evidence_digest": "sha256:" + repeat("6"), "completion_gpu_evidence_digest": "sha256:" + repeat("7"), "completion_gpu_identity_set_digest": "sha256:" + repeat("4"),
		"channel_binding_digest": "sha256:" + repeat("1"), "image_digest": request["image_digest"], "policy_digest": digestCanonical(request["policy"]),
		"input_digest": inputs[0].(map[string]any)["plaintext_digest_sha256"], "model_digest": inputs[1].(map[string]any)["plaintext_digest_sha256"],
		"result_digest": "sha256:" + repeat("8"), "artifact_manifest_digest": "sha256:" + repeat("9"), "secret_release_grant_digest": "sha256:" + repeat("d"),
		"outcome": "completed", "deletion_confirmed": true, "deletion_evidence_digest": "sha256:" + repeat("e"),
		"policy_registry_release": 1, "policy_registry_digest": "sha256:" + repeat("f"), "issued_at": now.Format("2006-01-02T15:04:05.000000Z"),
		"signing_key_id": "receipt-key-1", "signature": map[string]any{"algorithm": "ed25519", "value_base64": "unused-here"},
	}
	return receipt, admission, completion, expected
}

func TestLaunchReceiptBindsExactPolicyAndProtectedInputDigests(t *testing.T) {
	receipt, admission, completion, expected := launchReceiptFixture(t)
	if !validLaunchReceiptExact(receipt, admission, completion, expected) {
		t.Fatal("valid launch receipt fixture was rejected")
	}
	for _, field := range []string{"policy_digest", "input_digest", "model_digest"} {
		original := receipt[field]
		receipt[field] = "sha256:" + repeat("0")
		if validLaunchReceiptExact(receipt, admission, completion, expected) {
			t.Fatalf("launch receipt accepted substituted %s", field)
		}
		receipt[field] = original
	}
}
