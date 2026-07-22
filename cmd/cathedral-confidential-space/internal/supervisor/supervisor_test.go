package supervisor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func repeated(value string) string { return strings.Repeat(value, 64) }

func testChallenge(t *testing.T, protected []any) []byte {
	t.Helper()
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	protectedRaw, _ := contract.CanonicalJSON(protected)
	privateBytes := make([]byte, 32)
	privateBytes[0] = 1
	recipientPrivate, _ := ecdh.X25519().NewPrivateKey(privateBytes)
	expected := map[string]any{
		"schema": contract.ExpectedSchema, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"profile_authority": "gpu-profile:" + contract.ProfileID + "@profile=sha256:" + repeated("1") + "@release=1@registry=sha256:" + repeated("2"),
		"subject_hotkey":    "5Ftest", "evidence_format": "google_cloud_attestation_pki", "provider": "gcp",
		"machine_type": "a3-highgpu-1g", "project_id": "test-project", "zone": "us-central1-a",
		"gpu_type": "nvidia_h100_80gb", "gpu_count": 1, "provisioning_model": "spot",
		"provider_resource_id": "cathedral-attempt", "provider_instance_id": "123456", "source_image": "projects/cs/images/stable",
		"workload_service_account": "cc@test.iam.gserviceaccount.com", "attestation_audience": "https://kbs.example.com/cathedral",
		"worker_id": "11111111-1111-4111-8111-111111111111", "job_id": "22222222-2222-4222-8222-222222222222",
		"attempt_id": "33333333-3333-4333-8333-333333333333", "attempt_sequence": 1,
		"owner_digest": ownerDigest, "job_context_digest": "sha256:" + repeated("3"), "admission_nonce_digest": "sha256:" + repeated("4"),
		"request": map[string]any{
			"image": "us-docker.pkg.dev/test/cathedral/runtime@sha256:" + repeated("a"), "image_digest": "sha256:" + repeated("a"),
			"command": []any{"/usr/bin/python3", "/opt/cathedral/bin/cathedral-job"}, "protected_inputs": protected,
			"protected_input_set_digest": contract.Digest(protectedRaw),
			"artifacts":                  []any{map[string]any{"path": "result.json", "kind": "result", "max_bytes": 262144}},
			"output_recipient":           map[string]any{"algorithm": "x25519-hkdf-sha256-aes256gcm", "key_id": "customer-key-1", "public_key_base64": base64.StdEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())},
			"maximum_runtime_seconds":    60, "maximum_output_bytes": 262144, "retry_policy": "restart_from_zero",
			"policy": map[string]any{"egress": "control_plane_only", "control_plane_endpoints": []any{
				map[string]any{"purpose": "control_store", "origin": "https://storage.googleapis.com", "trust_anchor_sha256": "sha256:" + repeated("5")},
				map[string]any{"purpose": "kbs", "origin": "https://kbs.example.com", "trust_anchor_sha256": "sha256:" + repeated("6")},
			}},
		},
		"remaining_spend_micros": 100, "phase": "admission", "nonce_digest": "sha256:" + repeated("4"),
		"channel_key_sha256": nil, "channel_binding_sha256": nil, "verifier_digest": "sha256:" + repeated("7"),
	}
	raw, _ := contract.CanonicalJSON(map[string]any{"schema": contract.ChallengeSchema, "phase": "admission", "expected": expected, "finalize_sha256": nil})
	return raw
}

type fakeAttestor struct{ evidence AttestedEvidence }

func (attestor fakeAttestor) Collect(context.Context, []byte) (AttestedEvidence, error) {
	return attestor.evidence, nil
}
func (attestor fakeAttestor) CollectForEKM(context.Context, []byte, []byte) (AttestedEvidence, error) {
	return attestor.evidence, nil
}

type fakeKBS struct {
	privateKey ed25519.PrivateKey
	keyID      string
	now        time.Time
	inputs     []ProtectedInput
	evidence   AttestedEvidence
}

func (kbs fakeKBS) Release(_ context.Context, request ReleaseRequest, _ ChannelAttestor) (Release, error) {
	key := make([]byte, 32)
	noncePrefix := make([]byte, 8)
	challenge, _ := contract.ParseChallenge(testAdmissionChallenge, "admission")
	requestDocument := challenge.Expected["request"].(map[string]any)
	inputValues := requestDocument["protected_inputs"].([]any)
	sealedDigests := make([]any, len(inputValues))
	for index, rawInput := range inputValues {
		sealedDigests[index] = rawInput.(map[string]any)["sealed_record_sha256"]
	}
	recipientRaw, _ := contract.CanonicalJSON(requestDocument["output_recipient"])
	policy := map[string]any{
		"schema": contract.KBSReleasePolicySchema, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"job_id": request.Document["job_id"], "attempt_id": request.Document["attempt_id"], "job_context_digest": request.Document["job_context_digest"], "owner_digest": challenge.Expected["owner_digest"],
		"protected_input_set_digest": request.Document["protected_input_set_digest"], "sealed_record_sha256s": sealedDigests,
		"output_recipient_digest": contract.Digest(recipientRaw), "issued_at": kbs.now.Format("2006-01-02T15:04:05.000000Z"),
		"expires_at": kbs.now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": kbs.keyID,
	}
	policyUnsigned, _ := contract.CanonicalJSON(policy)
	policy["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(kbs.privateKey, policyUnsigned))}
	artifact, _ := contract.CanonicalJSON(policy)
	issued := kbs.now.Format("2006-01-02T15:04:05.000000Z")
	consumed := kbs.now.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
	expires := kbs.now.Add(time.Minute).Format("2006-01-02T15:04:05.000000Z")
	ack := map[string]any{
		"schema": ReleaseAckSchema, "grant_id": "44444444-4444-4444-8444-444444444444",
		"job_id": request.Document["job_id"], "attempt_id": request.Document["attempt_id"], "job_context_digest": request.Document["job_context_digest"],
		"channel_key_sha256": kbs.evidence.ChannelKeySHA256, "channel_binding_sha256": kbs.evidence.ChannelBindingSHA256,
		"protected_input_set_digest": request.Document["protected_input_set_digest"], "admission_evidence_sha256": contract.Digest(kbs.evidence.Canonical),
		"admission_token_sha256": kbs.evidence.TokenSHA256, "tls_ekm_sha256": kbs.evidence.TLSEKMSHA256,
		"one_time_nonce_digest": request.Document["one_time_nonce_digest"], "grant_artifact_sha256": contract.Digest(artifact),
		"release_request_sha256": contract.Digest(request.Canonical),
		"kbs_config_sha256":      "sha256:" + repeated("c"),
		"issued_at":              issued, "expires_at": expires, "single_use": true, "consumed_at": consumed, "signing_key_id": kbs.keyID,
	}
	unsigned, _ := contract.CanonicalJSON(ack)
	ack["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(kbs.privateKey, unsigned))}
	ackRaw, _ := contract.CanonicalJSON(ack)
	outputKey := make([]byte, 32)
	_, _ = rand.Read(outputKey)
	items := make([]EncryptedItem, len(kbs.inputs))
	for index, input := range kbs.inputs {
		items[index] = EncryptedItem{Kind: input.Kind, OwnerDigest: input.OwnerDigest, SealedReference: input.SealedReference, SealedRecordSHA256: input.SealedRecordSHA256, CiphertextSHA256: input.CiphertextSHA256, PlaintextSHA256: input.PlaintextSHA256, CiphertextBytes: input.CiphertextBytes, PlaintextBytes: input.PlaintextBytes, NoncePrefix: append([]byte(nil), noncePrefix...), Key: append([]byte(nil), key...)}
	}
	return Release{
		AckCanonical: ackRaw, ArtifactCanonical: artifact, OutputKey: outputKey, Evidence: kbs.evidence,
		Items: items,
	}, nil
}

func sealedInput(plaintext []byte, input ProtectedInput) []byte {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	aad, _ := contract.CanonicalJSON(map[string]any{"kind": input.Kind, "plaintext_sha256": input.PlaintextSHA256, "plaintext_bytes": input.PlaintextBytes, "chunk_index": uint32(0)})
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	stream := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(stream, uint32(len(ciphertext)))
	copy(stream[4:], ciphertext)
	return stream
}

type fakeInputStore struct{ objects map[string][]byte }

func (store fakeInputStore) Open(_ context.Context, reference string) (io.ReadCloser, error) {
	raw, ok := store.objects[reference]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

type fakeMount struct {
	root   string
	closed bool
}

func (mount *fakeMount) Root() string              { return mount.root }
func (mount *fakeMount) PrepareForWorkload() error { return nil }
func (mount *fakeMount) Close() error              { mount.closed = true; return os.RemoveAll(mount.root) }

type fakeSecrets struct{ mount *fakeMount }

func (store fakeSecrets) Mount(context.Context, string) (SecretMount, error) { return store.mount, nil }

type fakeSandbox struct{}

func (fakeSandbox) VerifyIsolation(context.Context) error { return nil }
func (fakeSandbox) Run(_ context.Context, _ []string, root string, _ int64) (SandboxResult, error) {
	if raw, err := os.ReadFile(filepath.Join(root, "model.bin")); err != nil || string(raw) != "protected model" {
		return SandboxResult{}, os.ErrInvalid
	}
	return SandboxResult{ExitCode: 0, Outputs: map[string][]byte{"result.json": []byte(`{"answer":42}`)}}, nil
}

type fakeUploader struct{ objects map[string][]byte }

func (uploader *fakeUploader) PutIfAbsent(_ context.Context, reference string, value []byte, _ string) error {
	if _, exists := uploader.objects[reference]; exists {
		return os.ErrExist
	}
	uploader.objects[reference] = append([]byte(nil), value...)
	return nil
}

type fakeControl struct {
	admission, release, completion, cleanup []byte
	evidence                                AttestedEvidence
	releaseAckDigest                        string
}

func (control *fakeControl) PublishAdmission(_ context.Context, raw []byte) error {
	control.admission = append([]byte(nil), raw...)
	return nil
}
func (control *fakeControl) PublishRelease(_ context.Context, requestRaw, raw, policy []byte) error {
	if contract.Digest(requestRaw) == "" {
		return os.ErrInvalid
	}
	if len(policy) == 0 {
		return os.ErrInvalid
	}
	control.release = append([]byte(nil), raw...)
	control.releaseAckDigest = contract.Digest(raw)
	return nil
}
func (control *fakeControl) PublishStatus(context.Context, string, map[string]any) error { return nil }
func (control *fakeControl) Cancellation(context.Context) <-chan struct{}                { return make(chan struct{}) }
func (control *fakeControl) PublishCompletion(_ context.Context, completion CompletionControl) error {
	control.completion = append([]byte(nil), completion.Evidence...)
	return nil
}
func (control *fakeControl) PublishCleanup(_ context.Context, raw []byte) error {
	control.cleanup = append([]byte(nil), raw...)
	return nil
}
func (control *fakeControl) WaitFinalize(_ context.Context, result, manifest string) (Finalize, error) {
	admissionValue, _ := contract.StrictJSON(testAdmissionChallenge)
	expected := admissionValue.(map[string]any)["expected"].(map[string]any)
	copyExpected := map[string]any{}
	for key, value := range expected {
		copyExpected[key] = value
	}
	copyExpected["phase"] = "completion"
	copyExpected["nonce_digest"] = "sha256:" + repeated("8")
	copyExpected["channel_key_sha256"] = control.evidence.ChannelKeySHA256
	copyExpected["channel_binding_sha256"] = control.evidence.ChannelBindingSHA256
	copyExpected["result_sha256"] = strings.TrimPrefix(result, "sha256:")
	copyExpected["artifact_manifest_sha256"] = strings.TrimPrefix(manifest, "sha256:")
	copyExpected["admission_bundle_sha256"] = repeated("9")
	copyExpected["admission_gpu_identity_set_sha256"] = repeated("a")
	copyExpected["kbs_release_ack_sha256"] = strings.TrimPrefix(control.releaseAckDigest, "sha256:")
	finalizeDigest := "sha256:" + repeated("b")
	raw, _ := contract.CanonicalJSON(map[string]any{"schema": contract.ChallengeSchema, "phase": "completion", "expected": copyExpected, "finalize_sha256": finalizeDigest})
	return Finalize{Challenge: raw, Digest: finalizeDigest}, nil
}

var testAdmissionChallenge []byte

func TestSupervisorFullSoftwareFlow(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	makeInput := func(kind, target, value, recordDigit string) (ProtectedInput, []byte) {
		plaintext := []byte(value)
		input := ProtectedInput{Kind: kind, OwnerDigest: ownerDigest, PlaintextSHA256: contract.Digest(plaintext), PlaintextBytes: int64(len(plaintext)), TargetName: target, SealedRecordSHA256: "sha256:" + repeated(recordDigit)}
		stream := sealedInput(plaintext, input)
		input.CiphertextSHA256 = contract.Digest(stream)
		input.SealedReference = "gs://test-control/customer/sealed-inputs/sha256/" + strings.TrimPrefix(input.CiphertextSHA256, "sha256:") + ".ccgpu"
		input.CiphertextBytes = int64(len(stream))
		return input, stream
	}
	input, inputStream := makeInput("input", "input.bin", "protected input", "8")
	model, modelStream := makeInput("model", "model.bin", "protected model", "9")
	inputs := []ProtectedInput{input, model}
	protected := make([]any, len(inputs))
	for index, item := range inputs {
		protected[index] = map[string]any{"kind": item.Kind, "owner_digest": item.OwnerDigest, "sealed_reference": item.SealedReference, "sealed_record_sha256": item.SealedRecordSHA256, "ciphertext_digest_sha256": item.CiphertextSHA256, "plaintext_digest_sha256": item.PlaintextSHA256, "ciphertext_bytes": item.CiphertextBytes, "plaintext_bytes": item.PlaintextBytes}
	}
	testAdmissionChallenge = testChallenge(t, protected)
	temporary := t.TempDir()
	mount := &fakeMount{root: filepath.Join(temporary, "secrets")}
	if err := os.Mkdir(mount.root, 0o700); err != nil {
		t.Fatal(err)
	}
	_, cleanupKey, _ := ed25519.GenerateKey(rand.Reader)
	_, kbsKey, _ := ed25519.GenerateKey(rand.Reader)
	evidence := AttestedEvidence{Canonical: []byte(`{"evidence":"google-pki"}`), TokenSHA256: "sha256:" + repeated("d"), ChannelKeySHA256: repeated("e"), ChannelBindingSHA256: repeated("f"), TLSEKMSHA256: "sha256:" + repeated("1")}
	control := &fakeControl{evidence: evidence}
	uploader := &fakeUploader{objects: map[string][]byte{}}
	supervisor := Supervisor{
		Attestor: fakeAttestor{evidence}, ChannelAttestor: fakeAttestor{evidence},
		KBS:     fakeKBS{privateKey: kbsKey, keyID: "kbs-1", now: now, inputs: inputs, evidence: evidence},
		Control: control, Secrets: fakeSecrets{mount}, Inputs: fakeInputStore{objects: map[string][]byte{input.SealedReference: inputStream, model.SealedReference: modelStream}}, Sandbox: fakeSandbox{},
		Outputs:    AESGCMOutputStore{Uploader: uploader, Prefix: "outputs/33333333"},
		CleanupKey: cleanupKey, TrustedKBSKeys: map[string]ed25519.PublicKey{"kbs-1": kbsKey.Public().(ed25519.PublicKey)},
		TrustedKBSConfigSHA256: "sha256:" + repeated("c"), KBSRegistrationAckSHA256: "sha256:" + repeated("d"), Now: func() time.Time { return now.Add(2 * time.Second) },
	}
	outcome, err := supervisor.Run(context.Background(), Request{AdmissionChallenge: testAdmissionChallenge, ProtectedInputs: inputs, Entrypoint: []string{"/usr/bin/python3", "/opt/cathedral/bin/cathedral-job"}, DeclaredArtifacts: []DeclaredArtifact{{Name: "result.json", Kind: "result", MaxBytes: 262144}}, MaximumRuntime: time.Minute, MaximumOutputBytes: 262144})
	if err != nil {
		t.Fatal(err)
	}
	if !contract.ValidDigest(outcome.ResultSHA256) || !contract.ValidDigest(outcome.ArtifactManifestSHA256) || len(control.admission) == 0 || len(control.release) == 0 || len(control.completion) == 0 || len(control.cleanup) == 0 || !mount.closed || len(uploader.objects) != 2 {
		t.Fatal("full supervisor flow did not persist every bounded stage and clean up")
	}
}

func TestSupervisorRejectsSubstitutedProtectedDeclaration(t *testing.T) {
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	input := ProtectedInput{Kind: "input", OwnerDigest: ownerDigest, SealedReference: "gs://test-control/customer/sealed-inputs/sha256/" + repeated("2") + ".ccgpu", SealedRecordSHA256: "sha256:" + repeated("8"), PlaintextSHA256: "sha256:" + repeated("1"), CiphertextSHA256: "sha256:" + repeated("2"), CiphertextBytes: 100, PlaintextBytes: 80, TargetName: "input.bin"}
	model := ProtectedInput{Kind: "model", OwnerDigest: ownerDigest, SealedReference: "gs://test-control/customer/sealed-inputs/sha256/" + repeated("4") + ".ccgpu", SealedRecordSHA256: "sha256:" + repeated("9"), PlaintextSHA256: "sha256:" + repeated("3"), CiphertextSHA256: "sha256:" + repeated("4"), CiphertextBytes: 100, PlaintextBytes: 80, TargetName: "model.bin"}
	committed := []any{map[string]any{"kind": input.Kind, "owner_digest": input.OwnerDigest, "sealed_reference": input.SealedReference, "sealed_record_sha256": input.SealedRecordSHA256, "ciphertext_digest_sha256": input.CiphertextSHA256, "plaintext_digest_sha256": input.PlaintextSHA256, "ciphertext_bytes": input.CiphertextBytes, "plaintext_bytes": input.PlaintextBytes}, map[string]any{"kind": model.Kind, "owner_digest": model.OwnerDigest, "sealed_reference": model.SealedReference, "sealed_record_sha256": model.SealedRecordSHA256, "ciphertext_digest_sha256": model.CiphertextSHA256, "plaintext_digest_sha256": model.PlaintextSHA256, "ciphertext_bytes": model.CiphertextBytes, "plaintext_bytes": model.PlaintextBytes}}
	challenge := testChallenge(t, committed)
	input.PlaintextSHA256 = "sha256:" + repeated("3")
	parsed, parseErr := contract.ParseChallenge(challenge, "admission")
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	err := validateProtectedInputs([]ProtectedInput{input, model}, parsed.Expected)
	if err == nil {
		t.Fatal("substituted protected input declaration was accepted")
	}
}

func TestSandboxTerminationWaitIsBounded(t *testing.T) {
	started := time.Now()
	if _, ok := waitSandbox(make(chan sandboxCompletion), 5*time.Millisecond); ok {
		t.Fatal("non-terminating sandbox was reported as stopped")
	}
	if time.Since(started) > time.Second {
		t.Fatal("sandbox shutdown wait exceeded its explicit bound")
	}
}
