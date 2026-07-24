package kbs

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func repeat(value string) string { return strings.Repeat(value, 64) }

func registrationFixture(t *testing.T, store JobStore) ([]byte, string, string, string) {
	t.Helper()
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	protected := make([]any, 0, 2)
	sealedDigests := make([]string, 0, 2)
	for index, item := range []struct{ kind, cipherDigit, plainDigit string }{{"input", "a", "b"}, {"model", "c", "d"}} {
		cipherDigest := "sha256:" + repeat(item.cipherDigit)
		reference := "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat(item.cipherDigit) + ".ccgpu"
		sealed := map[string]any{
			"schema": SealedRecordSchema, "kind": item.kind, "owner_digest": ownerDigest, "sealed_reference": reference,
			"ciphertext_sha256": cipherDigest, "plaintext_sha256": "sha256:" + repeat(item.plainDigit),
			"ciphertext_bytes": 1040, "plaintext_bytes": 1024,
			"nonce_prefix_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(7 + index)}, 8)),
			"key_base64":          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(8 + index)}, 32)),
		}
		sealedRaw, _ := contract.CanonicalJSON(sealed)
		sealedDigest, _, err := store.StoreSealed(sealedRaw)
		if err != nil {
			t.Fatal(err)
		}
		sealedDigests = append(sealedDigests, sealedDigest)
		protected = append(protected, map[string]any{
			"kind": item.kind, "owner_digest": ownerDigest, "sealed_reference": reference, "sealed_record_sha256": sealedDigest,
			"ciphertext_digest_sha256": cipherDigest, "plaintext_digest_sha256": "sha256:" + repeat(item.plainDigit),
			"ciphertext_bytes": 1040, "plaintext_bytes": 1024,
		})
	}
	protectedRaw, _ := contract.CanonicalJSON(protected)
	privateBytes := make([]byte, 32)
	privateBytes[0] = 1
	recipientPrivate, _ := ecdh.X25519().NewPrivateKey(privateBytes)
	jobID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	expected := map[string]any{
		"schema": contract.ExpectedSchema, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"profile_authority": "gpu-profile:" + contract.ProfileID + "@profile=sha256:" + repeat("1") + "@release=1@registry=sha256:" + repeat("2"),
		"subject_hotkey":    "5Ftest", "evidence_format": "google_cloud_attestation_pki", "provider": "gcp",
		"machine_type": "a3-highgpu-1g", "project_id": "test-project", "zone": "us-central1-a", "gpu_type": "nvidia_h100_80gb", "gpu_count": 1, "provisioning_model": "spot",
		"provider_resource_id": "cathedral-attempt", "provider_instance_id": "123456", "source_image": "projects/cs/images/stable", "workload_service_account": "cc@test.iam.gserviceaccount.com", "attestation_audience": "https://kbs.example.com/cathedral",
		"worker_id": "11111111-1111-4111-8111-111111111111", "job_id": jobID, "attempt_id": attemptID, "attempt_sequence": 1,
		"owner_digest": ownerDigest, "job_context_digest": "sha256:" + repeat("3"), "admission_nonce_digest": "sha256:" + repeat("4"),
		"request": map[string]any{
			"image": "us-docker.pkg.dev/test/cathedral/runtime@sha256:" + repeat("c"), "image_digest": "sha256:" + repeat("c"),
			"command": []any{"/usr/bin/python3", "/opt/cathedral/bin/cathedral-job"}, "protected_inputs": protected, "protected_input_set_digest": contract.Digest(protectedRaw),
			"artifacts":               []any{map[string]any{"path": "result.json", "kind": "result", "max_bytes": 262144}},
			"output_recipient":        map[string]any{"algorithm": "x25519-hkdf-sha256-aes256gcm", "key_id": "customer-key-1", "public_key_base64": base64.StdEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())},
			"maximum_runtime_seconds": 60, "maximum_output_bytes": 262144, "retry_policy": "restart_from_zero",
			"policy": map[string]any{"egress": "control_plane_only", "control_plane_endpoints": []any{
				map[string]any{"purpose": "control_store", "origin": "https://storage.googleapis.com", "trust_anchor_sha256": "sha256:" + repeat("5")},
				map[string]any{"purpose": "kbs", "origin": "https://kbs.example.com", "trust_anchor_sha256": "sha256:" + repeat("6")},
			}},
		},
		"remaining_spend_micros": 100, "phase": "admission", "nonce_digest": "sha256:" + repeat("4"), "channel_key_sha256": nil, "channel_binding_sha256": nil, "verifier_digest": "sha256:" + repeat("7"),
	}
	challengeRaw, _ := contract.CanonicalJSON(map[string]any{"schema": contract.ChallengeSchema, "phase": "admission", "expected": expected, "finalize_sha256": nil})
	registrationRaw, _ := contract.CanonicalJSON(map[string]any{
		"schema": JobRegistrationSchema, "expected": expected,
		"admission_challenge_base64": base64.StdEncoding.EncodeToString(challengeRaw),
	})
	return registrationRaw, sealedDigests[0], jobID, attemptID
}

type testCA struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	pool        *x509.CertPool
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return testCA{certificate: certificate, privateKey: key, pool: pool}
}

func (ca testCA) issue(t *testing.T, name string, server bool) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	result, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func handshakeOverPipe(serverConfig, clientConfig *tls.Config) (*tls.ConnectionState, error) {
	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverConnection := tls.Server(serverSide, serverConfig)
	clientConnection := tls.Client(clientSide, clientConfig)
	type result struct {
		state tls.ConnectionState
		err   error
	}
	serverResult := make(chan result, 1)
	clientResult := make(chan error, 1)
	go func() {
		err := serverConnection.Handshake()
		serverResult <- result{state: serverConnection.ConnectionState(), err: err}
	}()
	go func() { clientResult <- clientConnection.Handshake() }()
	clientErr := <-clientResult
	resultValue := <-serverResult
	_ = clientSide.Close()
	_ = serverSide.Close()
	if clientErr != nil {
		return nil, clientErr
	}
	if resultValue.err != nil {
		return nil, resultValue.err
	}
	return &resultValue.state, nil
}

func TestAdminJobRegistrationRequiresDedicatedMTLSCA(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	registrationRaw, _, _, _ := registrationFixture(t, store)
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	service := &Server{Jobs: store, SigningKey: signingKey, SigningKeyID: "kbs-1", ConfigSHA256: "sha256:" + repeat("e"), Now: func() time.Time { return time.Now().UTC() }}
	serverCA := newTestCA(t, "server-ca")
	adminCA := newTestCA(t, "admin-ca")
	wrongCA := newTestCA(t, "wrong-ca")
	serverConfiguration := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCA.issue(t, "localhost", true)}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: adminCA.pool}
	post := func(certificate *tls.Certificate) (*httptest.ResponseRecorder, error) {
		configuration := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: serverCA.pool, ServerName: "localhost"}
		if certificate != nil {
			configuration.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return certificate, nil }
		}
		state, err := handshakeOverPipe(serverConfiguration, configuration)
		if err != nil {
			return nil, err
		}
		request := httptest.NewRequest("POST", "https://kbs.example.com/v1/admin/jobs", bytes.NewReader(registrationRaw))
		request.TLS = state
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		return response, nil
	}
	response, err := post(nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != 404 {
		t.Fatalf("unauthenticated admin status=%d, want 404", response.Code)
	}
	wrong := wrongCA.issue(t, "wrong-admin", false)
	if _, err := post(&wrong); err == nil {
		t.Fatal("certificate outside dedicated admin CA completed TLS")
	}
	admin := adminCA.issue(t, "polaris-admin", false)
	response, err = post(&admin)
	if err != nil {
		t.Fatal(err)
	}
	body := response.Body.Bytes()
	if response.Code != 200 || bytes.Contains(body, []byte(`"key_base64"`)) || bytes.Contains(body, []byte(`"output_key_base64"`)) {
		t.Fatalf("authorized keyless registration status=%d body=%s", response.Code, body)
	}
}

func signedStagingAuthorization(t *testing.T, privateKey ed25519.PrivateKey, keyID, authorizationID string, record map[string]any, issued, expires time.Time) map[string]any {
	t.Helper()
	recordRaw, _ := contract.CanonicalJSON(record)
	authorization := map[string]any{
		"schema": SealedStageAuthorizationSchema, "authorization_id": authorizationID,
		"owner_digest": record["owner_digest"], "sealed_record_sha256": contract.Digest(recordRaw), "kind": record["kind"],
		"sealed_reference": record["sealed_reference"], "ciphertext_sha256": record["ciphertext_sha256"], "plaintext_sha256": record["plaintext_sha256"],
		"ciphertext_bytes": record["ciphertext_bytes"], "plaintext_bytes": record["plaintext_bytes"],
		"issued_at": issued.Format("2006-01-02T15:04:05.000000Z"), "expires_at": expires.Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": keyID,
	}
	unsigned, _ := contract.CanonicalJSON(authorization)
	authorization["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))}
	return authorization
}

func stagingRecord(ownerDigest string) map[string]any {
	return map[string]any{
		"schema": SealedRecordSchema, "kind": "input", "owner_digest": ownerDigest,
		"sealed_reference":  "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("e") + ".ccgpu",
		"ciphertext_sha256": "sha256:" + repeat("e"), "plaintext_sha256": "sha256:" + repeat("f"), "ciphertext_bytes": 1040, "plaintext_bytes": 1024,
		"nonce_prefix_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 8)), "key_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)),
	}
}

func TestStagingAuthorizationIsOwnerBoundAndExactlyRetryable(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	_, kbsSigningKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	service := &Server{
		Jobs: JobStore{Directory: t.TempDir()}, SigningKey: kbsSigningKey, SigningKeyID: "kbs-1", Now: func() time.Time { return now },
		StagingAuthorityKeys: map[string]ed25519.PublicKey{"polaris-staging-1": authorityPublic},
	}
	record := stagingRecord(contract.Digest([]byte("tenant-a-account")))
	authorization := signedStagingAuthorization(t, authorityPrivate, "polaris-staging-1", "44444444-4444-4444-8444-444444444444", record, now.Add(-time.Second), now.Add(4*time.Minute))
	requestRaw, _ := contract.CanonicalJSON(map[string]any{"schema": SealedStageRequestSchema, "sealed_record": record, "authorization": authorization})
	ackRaw, err := service.stageSealed(requestRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ackRaw, []byte(`"key_base64"`)) || bytes.Contains(ackRaw, []byte(`"nonce_prefix_base64"`)) {
		t.Fatal("staging acknowledgment leaks sealed-record key material")
	}
	value, _ := contract.StrictJSON(ackRaw)
	ack := value.(map[string]any)
	authorizationRaw, _ := contract.CanonicalJSON(authorization)
	if !contract.ExactKeys(ack, "schema", "sealed_record_sha256", "owner_digest", "sealed_reference", "ciphertext_sha256", "staging_authorization_sha256", "registered_at", "signing_key_id", "signature") || ack["schema"] != SealedStageAckSchema || ack["owner_digest"] != record["owner_digest"] || ack["staging_authorization_sha256"] != contract.Digest(authorizationRaw) {
		t.Fatal("staging acknowledgment lacks exact owner and authorization bindings")
	}
	if retryAck, err := service.stageSealed(requestRaw); err != nil || !bytes.Equal(retryAck, ackRaw) {
		t.Fatal("exact retry after a lost staging acknowledgment was not idempotent")
	}

	otherOwnerRecord := stagingRecord(contract.Digest([]byte("tenant-b-account")))
	otherAuthorization := signedStagingAuthorization(t, authorityPrivate, "polaris-staging-1", "55555555-5555-4555-8555-555555555555", otherOwnerRecord, now, now.Add(4*time.Minute))
	otherAuthorization["owner_digest"] = record["owner_digest"]
	unsigned := make(map[string]any, len(otherAuthorization)-1)
	for key, item := range otherAuthorization {
		if key != "signature" {
			unsigned[key] = item
		}
	}
	unsignedRaw, _ := contract.CanonicalJSON(unsigned)
	otherAuthorization["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivate, unsignedRaw))}
	otherRaw, _ := contract.CanonicalJSON(map[string]any{"schema": SealedStageRequestSchema, "sealed_record": otherOwnerRecord, "authorization": otherAuthorization})
	if _, err := service.stageSealed(otherRaw); err == nil {
		t.Fatal("signed staging authorization for another owner was accepted")
	}

	substituted := stagingRecord(record["owner_digest"].(string))
	substituted["ciphertext_sha256"] = "sha256:" + repeat("9")
	substituted["sealed_reference"] = "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("9") + ".ccgpu"
	substitutedAuthorization := signedStagingAuthorization(t, authorityPrivate, "polaris-staging-1", "44444444-4444-4444-8444-444444444444", substituted, now, now.Add(4*time.Minute))
	substitutedRaw, _ := contract.CanonicalJSON(map[string]any{"schema": SealedStageRequestSchema, "sealed_record": substituted, "authorization": substitutedAuthorization})
	if _, err := service.stageSealed(substitutedRaw); err == nil {
		t.Fatal("staging authorization ID was reused for a substituted signed record")
	}
}

func TestStagingAuthorizationRejectsStaleOrUntrustedSignatures(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	_, kbsSigningKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	service := &Server{Jobs: JobStore{Directory: t.TempDir()}, SigningKey: kbsSigningKey, SigningKeyID: "kbs-1", Now: func() time.Time { return now }, StagingAuthorityKeys: map[string]ed25519.PublicKey{"polaris-staging-1": authorityPublic}}
	record := stagingRecord(contract.Digest([]byte("tenant-a-account")))
	for name, authorization := range map[string]map[string]any{
		"stale":         signedStagingAuthorization(t, authorityPrivate, "polaris-staging-1", "66666666-6666-4666-8666-666666666666", record, now.Add(-10*time.Minute), now.Add(-5*time.Minute)),
		"untrusted":     signedStagingAuthorization(t, authorityPrivate, "unknown-key", "77777777-7777-4777-8777-777777777777", record, now, now.Add(5*time.Minute)),
		"zero_lifetime": signedStagingAuthorization(t, authorityPrivate, "polaris-staging-1", "88888888-8888-4888-8888-888888888888", record, now, now),
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := contract.CanonicalJSON(map[string]any{"schema": SealedStageRequestSchema, "sealed_record": record, "authorization": authorization})
			if _, err := service.stageSealed(raw); err == nil {
				t.Fatal("invalid staging authorization was accepted")
			}
		})
	}
}

func TestReleasePolicyRejectsZeroLifetime(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	store := JobStore{Directory: t.TempDir()}
	registrationRaw, _, _, _ := registrationFixture(t, store)
	registrationValue, _ := contract.StrictJSON(registrationRaw)
	expected := registrationValue.(map[string]any)["expected"].(map[string]any)
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	service := &Server{SigningKey: signingKey, SigningKeyID: "kbs-1"}
	policyRaw, err := service.releasePolicy(expected, now)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := contract.StrictJSON(policyRaw)
	policy := value.(map[string]any)
	policy["expires_at"] = policy["issued_at"]
	delete(policy, "signature")
	unsigned, _ := contract.CanonicalJSON(policy)
	policy["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, unsigned))}
	zeroLifetimeRaw, _ := contract.CanonicalJSON(policy)
	if _, err := contract.ValidateReleasePolicy(zeroLifetimeRaw, expected, now); err == nil {
		t.Fatal("zero-lifetime KBS release policy was accepted")
	}
}

func TestKeylessRegistrationGeneratesOutputKeyInsideKBS(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	registrationRaw, sealedDigest, jobID, attemptID := registrationFixture(t, store)
	if bytes.Contains(registrationRaw, []byte(`"key_base64"`)) || bytes.Contains(registrationRaw, []byte(`"output_key_base64"`)) {
		t.Fatal("Polaris job registration contains secret key material")
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	server := Server{Jobs: store, SigningKey: private, SigningKeyID: "kbs-1", Now: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }}
	adminCertificateDigest := "sha256:" + repeat("d")
	ackRaw, err := server.register(registrationRaw, adminCertificateDigest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ackRaw, []byte(`"key_base64"`)) || bytes.Contains(ackRaw, []byte(`"output_key_base64"`)) {
		t.Fatal("KBS registration acknowledgment leaks secret key material")
	}
	value, _ := contract.StrictJSON(ackRaw)
	ack := value.(map[string]any)
	if !contract.ExactKeys(ack, "schema", "job_id", "attempt_id", "job_context_digest", "owner_digest", "protected_input_set_digest", "sealed_record_sha256s", "job_record_sha256", "admin_client_certificate_sha256", "registered_at", "signing_key_id", "signature") || ack["schema"] != JobRegistrationAckSchema || ack["owner_digest"] != contract.Digest([]byte("tenant-a-account")) || ack["admin_client_certificate_sha256"] != adminCertificateDigest || ack["sealed_record_sha256s"].([]any)[0] != sealedDigest {
		t.Fatal("KBS registration acknowledgment is not exact and identity-bound")
	}
	signature := ack["signature"].(map[string]any)
	signatureRaw, _ := base64.StdEncoding.Strict().DecodeString(signature["value_base64"].(string))
	delete(ack, "signature")
	unsigned, _ := contract.CanonicalJSON(ack)
	if !ed25519.Verify(public, unsigned, signatureRaw) {
		t.Fatal("KBS registration acknowledgment signature is invalid")
	}
	record, err := store.Load(jobID, attemptID)
	if err != nil || len(record.OutputKey) != 32 || len(record.EncryptedItems) != 2 {
		t.Fatal("KBS did not internally resolve input keys and generate an output key")
	}
	item := record.EncryptedItems[0].(map[string]any)
	if item["sealed_record_sha256"] != sealedDigest || item["key_base64"] == "" {
		t.Fatal("KBS internal record is not bound to the sealed input record")
	}
}

func TestSealedCiphertextHasOneKeyRecord(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	_, _, _, _ = registrationFixture(t, store)
	conflict := map[string]any{
		"schema": SealedRecordSchema, "kind": "input", "owner_digest": contract.Digest([]byte("tenant-a-account")), "sealed_reference": "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("a") + ".ccgpu",
		"ciphertext_sha256": "sha256:" + repeat("a"), "plaintext_sha256": "sha256:" + repeat("b"), "ciphertext_bytes": 1040, "plaintext_bytes": 1024,
		"nonce_prefix_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 8)), "key_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
	}
	raw, _ := contract.CanonicalJSON(conflict)
	if _, _, err := store.StoreSealed(raw); err == nil {
		t.Fatal("same ciphertext was bound to a second data key record")
	}
}

func TestSealedCiphertextCannotBeReboundToAnotherOwner(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	_, _, _, _ = registrationFixture(t, store)
	rebound := map[string]any{
		"schema": SealedRecordSchema, "kind": "input", "owner_digest": contract.Digest([]byte("tenant-b-account")),
		"sealed_reference":  "gs://test-bucket/customer/sealed-inputs/sha256/" + repeat("a") + ".ccgpu",
		"ciphertext_sha256": "sha256:" + repeat("a"), "plaintext_sha256": "sha256:" + repeat("b"), "ciphertext_bytes": 1040, "plaintext_bytes": 1024,
		"nonce_prefix_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 8)), "key_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)),
	}
	raw, _ := contract.CanonicalJSON(rebound)
	if _, _, err := store.StoreSealed(raw); err == nil {
		t.Fatal("same ciphertext was rebound from one owner digest to another")
	}
}

func TestRegisteredSealedRecordCannotBeReusedByAnotherOwner(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	registrationRaw, _, _, _ := registrationFixture(t, store)
	value, _ := contract.StrictJSON(registrationRaw)
	registration := value.(map[string]any)
	expected := registration["expected"].(map[string]any)
	otherOwner := contract.Digest([]byte("tenant-b-account"))
	expected["owner_digest"] = otherOwner
	request := expected["request"].(map[string]any)
	inputs := request["protected_inputs"].([]any)
	for _, rawInput := range inputs {
		rawInput.(map[string]any)["owner_digest"] = otherOwner
	}
	inputsRaw, _ := contract.CanonicalJSON(inputs)
	request["protected_input_set_digest"] = contract.Digest(inputsRaw)
	challengeRaw, _ := contract.CanonicalJSON(map[string]any{"schema": contract.ChallengeSchema, "phase": "admission", "expected": expected, "finalize_sha256": nil})
	registration["admission_challenge_base64"] = base64.StdEncoding.EncodeToString(challengeRaw)
	registrationRaw, _ = contract.CanonicalJSON(registration)
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	service := &Server{Jobs: store, SigningKey: signingKey, SigningKeyID: "kbs-1", Now: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }}
	if _, err := service.register(registrationRaw, "sha256:"+repeat("d")); err == nil {
		t.Fatal("another owner reused sealed records registered to the first owner")
	}
}

func TestReleaseConsumptionIsOncePerAttemptAcrossNonceChanges(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	jobID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	first := []byte(`{"schema":"cathedral_cc_gpu_kbs_release_response_v1"}`)
	if committed, err := store.CommitRelease(jobID, attemptID, "sha256:"+repeat("1"), first); err != nil || !bytes.Equal(committed, first) {
		t.Fatal(err)
	}
	if replay, err := store.CommitRelease(jobID, attemptID, "sha256:"+repeat("1"), []byte(`{"schema":"cathedral_cc_gpu_kbs_release_response_v1","ignored":true}`)); err != nil || !bytes.Equal(replay, first) {
		t.Fatal("exact release retry did not recover the committed response")
	}
	if _, err := store.CommitRelease(jobID, attemptID, "sha256:"+repeat("2"), first); err == nil {
		t.Fatal("changed nonce/request obtained a second release")
	}
}

func TestConcurrentReleaseConsumptionHasOneWinner(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	var winners atomic.Int64
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func(value byte) {
			defer group.Done()
			response := []byte(`{"schema":"cathedral_cc_gpu_kbs_release_response_v1","winner":` + strconv.Itoa(int(value)) + `}`)
			if _, err := store.CommitRelease("22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", contract.Digest([]byte{value}), response); err == nil {
				winners.Add(1)
			}
		}(byte(index))
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("release winners=%d, want 1", winners.Load())
	}
}

func TestCompletionChallengeCannotBeSubstitutedForAttempt(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	jobID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	first := []byte(`{"challenge":1}`)
	second := []byte(`{"challenge":2}`)
	firstDigest := contract.Digest(first)
	if err := store.BeginCompletion(jobID, attemptID, firstDigest, first); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCompletion(jobID, attemptID, contract.Digest(second), second); err == nil {
		t.Fatal("attempt accepted a substituted completion challenge")
	}
	if _, err := store.ReadCompletion(jobID, attemptID, firstDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	requestDigest := contract.Digest([]byte("completion-request"))
	response := []byte(`{"schema":"cathedral_cc_gpu_kbs_completion_ack_v1","verified":true}`)
	if committed, err := store.CommitCompletion(jobID, attemptID, firstDigest, requestDigest, response); err != nil || !bytes.Equal(committed, response) {
		t.Fatal(err)
	}
	if committed, exists, err := store.CompletionResponse(jobID, attemptID, firstDigest, requestDigest); err != nil || !exists || !bytes.Equal(committed, response) {
		t.Fatal("exact completion retry did not recover the committed response")
	}
	if _, exists, err := store.CompletionResponse(jobID, attemptID, firstDigest, contract.Digest([]byte("different-request"))); err == nil || !exists {
		t.Fatal("changed completion request reused a consumed challenge")
	}
	if err := store.BeginCompletion(jobID, attemptID, firstDigest, first); err == nil {
		t.Fatal("consumed completion attempt restarted")
	}
}

func TestCompletionChallengeStartIsExactlyRetryableBeforeConsumption(t *testing.T) {
	store := JobStore{Directory: t.TempDir()}
	jobID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	challenge := []byte(`{"challenge":1}`)
	digest := contract.Digest(challenge)
	if err := store.BeginCompletion(jobID, attemptID, digest, challenge); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCompletion(jobID, attemptID, digest, challenge); err != nil {
		t.Fatal("exact completion challenge retry was rejected")
	}
}
