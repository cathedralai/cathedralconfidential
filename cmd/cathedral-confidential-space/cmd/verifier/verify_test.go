package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

type testPKI struct {
	root         *x509.Certificate
	leafKey      *rsa.PrivateKey
	certificates []string
}

func makePKI(t *testing.T, now time.Time) testPKI {
	t.Helper()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intermediateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial := int64(1)
	certificate := func(commonName string, isCA bool, public any, parent *x509.Certificate, parentKey any) (*x509.Certificate, []byte) {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: isCA,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		}
		serial++
		if isCA {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = template, rootKey
		}
		raw, err := x509.CreateCertificate(rand.Reader, template, parent, public, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := x509.ParseCertificate(raw)
		return parsed, raw
	}
	root, rootRaw := certificate("Google test root", true, &rootKey.PublicKey, nil, nil)
	intermediate, intermediateRaw := certificate("Google test intermediate", true, &intermediateKey.PublicKey, root, rootKey)
	_, leafRaw := certificate("Google test leaf", false, &leafKey.PublicKey, intermediate, intermediateKey)
	return testPKI{root: root, leafKey: leafKey, certificates: []string{
		base64.StdEncoding.EncodeToString(leafRaw), base64.StdEncoding.EncodeToString(intermediateRaw), base64.StdEncoding.EncodeToString(rootRaw),
	}}
}

func repeat(character string) string {
	result := ""
	for len(result) < 64 {
		result += character
	}
	return result[:64]
}

func testPolicy(pki testPKI) *verifierPolicy {
	return &verifierPolicy{
		Schema: policySchema, ProfileID: contract.ProfileID,
		ProfileAuthority: "gpu-profile:" + contract.ProfileID + "@profile=sha256:" + repeat("1") + "@release=1@registry=sha256:" + repeat("2"),
		Audience:         "https://kbs.example.com/cathedral", ProjectID: "test-project", Zone: "us-central1-a",
		SourceImage:               "projects/confidential-space-images/global/images/confidential-space-260700",
		WorkloadServiceAccount:    "cc-gpu@test-project.iam.gserviceaccount.com",
		AllowedInstanceNamePrefix: "cathedral-attempt-", AllowedSWVersions: []string{"260700"},
		MinimumTDXTCBDate: "2026-07-01T00:00:00Z", AllowedTDXTCBStatuses: []string{"UpToDate"},
		AllowedNVIDIADrivers: []string{"590.48.01"}, AllowedNVIDIAVBIOS: []string{"96.00.CF.00.01"},
		TrustedKBSConfigSHA256: "sha256:" + repeat("c"),
		Container: containerPolicy{
			ImageDigest: "sha256:" + repeat("a"), ImageReference: "us-docker.pkg.dev/test/workload@sha256:" + repeat("a"),
			Args:        []string{"/opt/cathedral/collector", "serve", "--listen", ":8443"},
			Environment: map[string]any{"CATHEDRAL_PROFILE": contract.ProfileID}, RestartPolicy: "Never",
		},
		MaxTokenAgeSeconds: 600, MaxClockSkewSeconds: 5, MaxDeletionAgeSeconds: 3600, MaxReleaseToReceiptSeconds: 3600, ConfidentialSpaceRootCert: pki.root,
	}
}

func testExpected(t *testing.T, policy *verifierPolicy, phase string, channelKey, channelBinding string) map[string]any {
	t.Helper()
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	recipientPrivateBytes := make([]byte, 32)
	recipientPrivateBytes[0] = 1
	recipientPrivate, _ := ecdh.X25519().NewPrivateKey(recipientPrivateBytes)
	jobPolicy := map[string]any{
		"egress": "control_plane_only",
		"control_plane_endpoints": []any{
			map[string]any{"purpose": "control_store", "origin": "https://storage.googleapis.com", "trust_anchor_sha256": "sha256:" + repeat("b")},
			map[string]any{"purpose": "kbs", "origin": "https://kbs.example.com", "trust_anchor_sha256": "sha256:" + repeat("c")},
		},
	}
	protectedInputs := []any{
		map[string]any{"kind": "input", "owner_digest": ownerDigest, "sealed_reference": "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("1") + ".ccgpu", "sealed_record_sha256": "sha256:" + repeat("2"), "ciphertext_digest_sha256": "sha256:" + repeat("1"), "plaintext_digest_sha256": "sha256:" + repeat("3"), "ciphertext_bytes": 1040, "plaintext_bytes": 1024},
		map[string]any{"kind": "model", "owner_digest": ownerDigest, "sealed_reference": "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("4") + ".ccgpu", "sealed_record_sha256": "sha256:" + repeat("5"), "ciphertext_digest_sha256": "sha256:" + repeat("4"), "plaintext_digest_sha256": "sha256:" + repeat("6"), "ciphertext_bytes": 1040, "plaintext_bytes": 1024},
	}
	protectedRaw, _ := contract.CanonicalJSON(protectedInputs)
	expected := map[string]any{
		"schema": contract.ExpectedSchema, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"profile_authority": policy.ProfileAuthority, "subject_hotkey": "5FtestHotkey", "evidence_format": "google_cloud_attestation_pki", "provider": "gcp",
		"machine_type": "a3-highgpu-1g", "project_id": policy.ProjectID, "zone": policy.Zone,
		"gpu_type": "nvidia_h100_80gb", "gpu_count": 1, "provisioning_model": "spot",
		"provider_resource_id": "cathedral-attempt-33333333", "provider_instance_id": "987654321",
		"source_image": policy.SourceImage, "workload_service_account": policy.WorkloadServiceAccount, "attestation_audience": policy.Audience,
		"worker_id": "11111111-1111-4111-8111-111111111111", "job_id": "22222222-2222-4222-8222-222222222222",
		"attempt_id": "33333333-3333-4333-8333-333333333333", "attempt_sequence": 1,
		"owner_digest": ownerDigest, "job_context_digest": "sha256:" + repeat("d"), "admission_nonce_digest": "sha256:" + repeat("e"),
		"request": map[string]any{
			"policy": jobPolicy, "protected_input_set_digest": contract.Digest(protectedRaw),
			"image": policy.Container.ImageReference, "image_digest": policy.Container.ImageDigest,
			"command": []any{"/usr/bin/python3", "/opt/cathedral/bin/cathedral-job"}, "protected_inputs": protectedInputs,
			"artifacts":               []any{map[string]any{"path": "result.json", "kind": "result", "max_bytes": 262144}},
			"output_recipient":        map[string]any{"algorithm": "x25519-hkdf-sha256-aes256gcm", "key_id": "customer-key-1", "public_key_base64": base64.StdEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())},
			"maximum_runtime_seconds": 60, "maximum_output_bytes": 262144, "retry_policy": "restart_from_zero",
		},
		"remaining_spend_micros": 1_000_000, "phase": phase, "nonce_digest": "sha256:" + repeat("e"),
		"channel_key_sha256": nil, "channel_binding_sha256": nil, "verifier_digest": "sha256:" + repeat("9"),
	}
	if phase == "completion" {
		expected["nonce_digest"] = "sha256:" + repeat("3")
		expected["channel_key_sha256"] = channelKey
		expected["channel_binding_sha256"] = channelBinding
		expected["result_sha256"] = repeat("4")
		expected["artifact_manifest_sha256"] = repeat("5")
		expected["admission_bundle_sha256"] = repeat("6")
		expected["admission_gpu_identity_set_sha256"] = repeat("7")
		expected["kbs_release_ack_sha256"] = repeat("8")
	}
	return expected
}

func signedJWT(t *testing.T, pki testPKI, claims map[string]any) string {
	t.Helper()
	headerRaw, _ := contract.CanonicalJSON(map[string]any{"alg": "RS256", "typ": "JWT", "x5c": stringsToAny(pki.certificates)})
	claimsRaw, _ := contract.CanonicalJSON(claims)
	header := base64.RawURLEncoding.EncodeToString(headerRaw)
	payload := base64.RawURLEncoding.EncodeToString(claimsRaw)
	signed := header + "." + payload
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, pki.leafKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testClaims(now time.Time, policy *verifierPolicy, nonces []string) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": policy.Audience, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"eat_nonce": stringsToAny(nonces), "attester_tcb": []any{"INTEL"}, "hwmodel": "GCP_INTEL_TDX",
		"oemid": 11129, "secboot": true, "dbgstat": "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE", "swversion": []any{"260700"},
		"google_service_accounts": []any{policy.WorkloadServiceAccount},
		"sub":                     "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/987654321",
		"tdx":                     []any{map[string]any{"gcp_attester_tcb_status": "UpToDate", "gcp_attester_tcb_date": "2026-07-17T00:00:00Z"}},
		"submods": map[string]any{
			"confidential_space": map[string]any{"support_attributes": []any{"STABLE", "USABLE"}, "monitoring_enabled": map[string]any{"memory": false}},
			"container": map[string]any{
				"args": stringsToAny(policy.Container.Args), "cmd_override": []any{}, "env": policy.Container.Environment,
				"env_override": map[string]any{}, "image_digest": policy.Container.ImageDigest, "image_id": "sha256:" + repeat("8"),
				"image_reference": policy.Container.ImageReference, "image_signatures": []any{}, "restart_policy": "Never",
			},
			"gce": map[string]any{"instance_id": "987654321", "instance_name": "cathedral-attempt-33333333", "project_id": policy.ProjectID, "project_number": "123456", "zone": policy.Zone},
			"nvidia_gpu": map[string]any{"cc_feature": "SPT", "cc_mode": "ON", "gpus": []any{map[string]any{
				"driver_version": "590.48.01", "hwmodel": "GCP_NVIDIA_H100", "l4_serial_number": "aabbcc", "ueid": "01020304", "vbios_version": "96.00.CF.00.01",
			}}},
		},
	}
}

func testVerifierInput(t *testing.T, now time.Time, pki testPKI, policy *verifierPolicy, mutate func(map[string]any)) []byte {
	t.Helper()
	expected := testExpected(t, policy, "admission", "", "")
	challengeRaw, _ := contract.CanonicalJSON(map[string]any{"schema": contract.ChallengeSchema, "phase": "admission", "expected": expected, "finalize_sha256": nil})
	challenge, err := contract.ParseChallenge(challengeRaw, "admission")
	if err != nil {
		t.Fatal(err)
	}
	_, channelKey, _ := ed25519.GenerateKey(rand.Reader)
	ready, _ := contract.ReadyAssertion(challenge, channelKey.Public().(ed25519.PublicKey), contract.LocalGPU{Model: "NVIDIA H100 80GB", UUIDSHA256: "sha256:" + repeat("1"), Count: 1, Ready: true})
	ekm := []byte("0123456789abcdef0123456789abcdef")
	nonces, _ := contract.TokenNonces(challenge, ekm, ready)
	claims := testClaims(now, policy, nonces)
	if mutate != nil {
		mutate(claims)
	}
	token := signedJWT(t, pki, claims)
	evidence, _ := contract.SignedProof(challenge, token, nonces, ready, ekm, channelKey)
	input, _ := contract.CanonicalJSON(map[string]any{"expected": expected, "evidence": evidence, "tls_ekm_sha256": contract.Digest(ekm), "finalize_sha256": nil})
	return input
}

func TestPolarisAndValidatorReplayModesShareOnePKIToken(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	pki := makePKI(t, now)
	policy := testPolicy(pki)
	raw := testVerifierInput(t, now, pki, policy, nil)
	verdict, err := verifyInput(raw, "admission", policy, now, "sha256:"+repeat("9"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := verdict["evidence_artifacts"].(map[string]any)
	bundle, _ := base64.StdEncoding.DecodeString(artifacts["bundle"].(string))
	replayValue, err := contract.StrictJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	replay := replayValue.(map[string]any)
	replayInput, _ := contract.CanonicalJSON(map[string]any{"expected": replay["expected"], "evidence": replay["evidence"], "tls_ekm_sha256": replay["tls_ekm_sha256"], "finalize_sha256": replay["finalize_sha256"]})
	replayed, err := verifyInput(replayInput, "admission", policy, now, "sha256:"+repeat("9"))
	if err != nil {
		t.Fatal(err)
	}
	if replayed["gpu_identity_set_sha256"] != verdict["gpu_identity_set_sha256"] || replayed["bundle_sha256"] != verdict["bundle_sha256"] {
		t.Fatal("validator replay changed the verified evidence identity")
	}
}

func TestVerifierRejectsAdversarialCompositeClaims(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	pki := makePKI(t, now)
	policy := testPolicy(pki)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"gpu cc off", func(claims map[string]any) {
			claims["submods"].(map[string]any)["nvidia_gpu"].(map[string]any)["cc_mode"] = "OFF"
		}},
		{"two gpus", func(claims map[string]any) {
			gpu := claims["submods"].(map[string]any)["nvidia_gpu"].(map[string]any)
			gpu["gpus"] = append(gpu["gpus"].([]any), gpu["gpus"].([]any)[0])
		}},
		{"debug", func(claims map[string]any) { claims["dbgstat"] = "enabled" }},
		{"not stable", func(claims map[string]any) {
			claims["submods"].(map[string]any)["confidential_space"].(map[string]any)["support_attributes"] = []any{"USABLE"}
		}},
		{"wrong container", func(claims map[string]any) {
			claims["submods"].(map[string]any)["container"].(map[string]any)["image_digest"] = "sha256:" + repeat("0")
		}},
		{"stale", func(claims map[string]any) { claims["iat"] = now.Add(-2 * time.Hour).Unix() }},
		{"nonce removed", func(claims map[string]any) { claims["eat_nonce"] = claims["eat_nonce"].([]any)[:3] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := testVerifierInput(t, now, pki, policy, test.mutate)
			if _, err := verifyInput(raw, "admission", policy, now, "sha256:"+repeat("9")); err == nil {
				t.Fatal("adversarial token was accepted")
			}
		})
	}
}

var _ = json.Number("")
