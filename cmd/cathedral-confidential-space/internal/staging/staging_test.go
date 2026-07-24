package staging

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

type staticToken string

func (token staticToken) Token(context.Context) (string, error) { return string(token), nil }

func TestStageEncryptsUploadsAndRegistersKeyDirectlyWithKBS(t *testing.T) {
	plaintext := bytes.Repeat([]byte("protected-H100-vector\x00"), 300000)
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	var authorizationAccepted bool
	var kbsAccepted bool
	var uploaded []byte
	gcsServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			_, _ = response.Write(uploaded)
			return
		}
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer test-token" || request.URL.Query().Get("ifGenerationMatch") != "0" {
			t.Errorf("unexpected GCS request: %s %s", request.Method, request.URL.String())
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if !authorizationAccepted || !kbsAccepted {
			t.Error("ciphertext upload occurred before owner authorization and KBS registration")
		}
		uploaded, _ = io.ReadAll(request.Body)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"name": request.URL.Query().Get("name"), "generation": "7", "size": json.Number(lenNumber(uploaded)).String()})
	}))
	defer gcsServer.Close()
	now := time.Date(2026, 7, 22, 4, 0, 0, 0, time.UTC)
	kbsPublic, kbsPrivate, _ := ed25519.GenerateKey(nil)
	authorityPublic, authorityPrivate, _ := ed25519.GenerateKey(nil)
	ownerDigest := contract.Digest([]byte("tenant-a-account"))
	var authorizationRaw []byte
	polarisServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-api-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == StagingBindingPath {
			raw, _ := contract.CanonicalJSON(map[string]any{"schema": BindingSchema, "owner_digest": ownerDigest, "profile_id": contract.ProfileID})
			_, _ = response.Write(raw)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != StagingAuthorizationPath {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		requestRaw, _ := io.ReadAll(request.Body)
		if bytes.Contains(requestRaw, []byte("owner_digest")) || bytes.Contains(requestRaw, []byte("key_base64")) || bytes.Contains(requestRaw, []byte("nonce_prefix_base64")) {
			t.Error("Polaris staging authorization request received owner or secret key material")
		}
		value, _ := contract.StrictJSON(requestRaw)
		declaration := value.(map[string]any)
		authorization := map[string]any{
			"schema": AuthorizationSchema, "authorization_id": "11111111-1111-4111-8111-111111111111", "owner_digest": ownerDigest,
			"sealed_record_sha256": declaration["sealed_record_sha256"], "kind": declaration["kind"], "sealed_reference": declaration["sealed_reference"],
			"ciphertext_sha256": declaration["ciphertext_digest_sha256"], "plaintext_sha256": declaration["plaintext_digest_sha256"], "ciphertext_bytes": declaration["ciphertext_bytes"], "plaintext_bytes": declaration["plaintext_bytes"],
			"issued_at": now.Format("2006-01-02T15:04:05.000000Z"), "expires_at": now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": "staging-test",
		}
		unsigned, _ := contract.CanonicalJSON(authorization)
		authorization["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivate, unsigned))}
		authorizationRaw, _ = contract.CanonicalJSON(authorization)
		authorizationAccepted = true
		_, _ = response.Write(authorizationRaw)
	}))
	defer polarisServer.Close()
	var registered map[string]any
	kbsServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/staging/sealed-inputs" {
			t.Errorf("unexpected KBS request: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(request.Body)
		value, err := contract.StrictJSON(raw)
		if err != nil {
			t.Errorf("record is not strict JSON: %v", err)
		}
		wrapper, _ := value.(map[string]any)
		registered, _ = wrapper["sealed_record"].(map[string]any)
		kbsAccepted = true
		recordRaw, _ := contract.CanonicalJSON(registered)
		ack := map[string]any{
			"schema": SealedRegistrationAckSchema, "sealed_record_sha256": contract.Digest(recordRaw),
			"sealed_reference": registered["sealed_reference"], "ciphertext_sha256": registered["ciphertext_sha256"],
			"owner_digest":                 registered["owner_digest"],
			"staging_authorization_sha256": contract.Digest(authorizationRaw), "registered_at": now.Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": "kbs-test",
		}
		unsigned, _ := contract.CanonicalJSON(ack)
		ack["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(kbsPrivate, unsigned))}
		encoded, _ := contract.CanonicalJSON(ack)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(encoded)
	}))
	defer kbsServer.Close()
	gcs := &GCSClient{Origin: gcsServer.URL, Client: gcsServer.Client(), Tokens: staticToken("test-token")}
	polaris := &PolarisClient{Origin: polarisServer.URL, Client: polarisServer.Client(), BearerToken: []byte("test-api-token"), SigningKeyID: "staging-test", SigningPublicKey: authorityPublic, Now: func() time.Time { return now }}
	kbs := &KBSClient{Origin: kbsServer.URL, Client: kbsServer.Client(), SigningKeyID: "kbs-test", SigningPublicKey: kbsPublic, Now: func() time.Time { return now }}
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 40))
	declaration, err := Stage(context.Background(), Options{InputPath: inputPath, Kind: "input", Bucket: "cc-inputs", Prefix: "tenant-a", TempDir: directory, GCS: gcs, Polaris: polaris, KBS: kbs, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	if declaration.SealedRecordSHA256 == "" || declaration.OwnerDigest != ownerDigest || declaration.PlaintextBytes != int64(len(plaintext)) || declaration.CiphertextBytes != int64(len(uploaded)) || strings.Contains(mustJSON(t, declaration), "owner_digest") || strings.Contains(mustJSON(t, declaration), "QkJCQkJC") || strings.Contains(mustJSON(t, declaration), "tenant-a-account") {
		t.Fatal("public declaration is incomplete or leaks key material")
	}
	if declaration.PlaintextDigestSHA256 != contract.Digest(plaintext) || declaration.CiphertextDigestSHA256 != contract.Digest(uploaded) || !contract.ValidSealedReference(declaration.SealedReference, declaration.CiphertextDigestSHA256) {
		t.Fatal("public declaration does not bind exact plaintext/ciphertext")
	}
	if registered["key_base64"] == nil || registered["nonce_prefix_base64"] == nil || registered["sealed_reference"] != declaration.SealedReference || registered["owner_digest"] != ownerDigest {
		t.Fatal("KBS did not receive the sealed key record directly")
	}
	decrypted := decryptFixture(t, uploaded, registered)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("staging wire format does not decrypt to the original bytes")
	}
}

func TestGCSExistingContentAddressMustMatch(t *testing.T) {
	payload := []byte("immutable ciphertext")
	digest := contract.Digest(payload)
	for _, test := range []struct {
		name     string
		existing []byte
		status   int
		wantErr  bool
	}{
		{"matching_precondition", payload, http.StatusPreconditionFailed, false},
		{"matching_lost_metadata", payload, http.StatusOK, false},
		{"conflict", []byte("different ciphertext"), http.StatusPreconditionFailed, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost {
					response.WriteHeader(test.status)
					if test.status == http.StatusOK {
						_, _ = response.Write([]byte(`{}`))
					}
					return
				}
				_, _ = response.Write(test.existing)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "sealed.ccgpu")
			_ = os.WriteFile(path, payload, 0o600)
			client := &GCSClient{Origin: server.URL, Client: server.Client(), Tokens: staticToken("token")}
			err := client.UploadIfAbsent(context.Background(), "bucket", "tenant/sealed-inputs/sha256/x.ccgpu", path, digest, int64(len(payload)))
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestRegisterSealedRejectsTamperedAck(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 7, 22, 4, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization := []byte(`{}`)
		ack := map[string]any{
			"schema": SealedRegistrationAckSchema, "sealed_record_sha256": contract.Digest([]byte("record")),
			"sealed_reference":  "gs://bucket/tenant/sealed-inputs/sha256/" + strings.Repeat("a", 64) + ".ccgpu",
			"ciphertext_sha256": "sha256:" + strings.Repeat("a", 64), "owner_digest": contract.Digest([]byte("owner")), "staging_authorization_sha256": contract.Digest(authorization),
			"registered_at": now.Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": "key",
		}
		unsigned, _ := contract.CanonicalJSON(ack)
		signature := ed25519.Sign(private, unsigned)
		signature[0] ^= 0xff
		ack["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(signature)}
		encoded, _ := contract.CanonicalJSON(ack)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(encoded)
	}))
	defer server.Close()
	client := &KBSClient{Origin: server.URL, Client: server.Client(), SigningKeyID: "key", SigningPublicKey: public, Now: func() time.Time { return now }}
	reference := "gs://bucket/tenant/sealed-inputs/sha256/" + strings.Repeat("a", 64) + ".ccgpu"
	if _, err := client.RegisterSealed(context.Background(), []byte(`{}`), []byte(`{}`), reference, "sha256:"+strings.Repeat("a", 64), contract.Digest([]byte("owner"))); err == nil {
		t.Fatal("tampered KBS registration signature was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestPolarisAuthorizationFailsClosedOnOwnerTimeAndSignature(t *testing.T) {
	now := time.Date(2026, 7, 22, 4, 0, 0, 0, time.UTC)
	public, private, _ := ed25519.GenerateKey(nil)
	owner := contract.Digest([]byte("owner"))
	declaration := map[string]any{
		"kind": "input", "sealed_reference": "gs://bucket/tenant/sealed-inputs/sha256/" + strings.Repeat("a", 64) + ".ccgpu",
		"sealed_record_sha256": "sha256:" + strings.Repeat("b", 64), "ciphertext_digest_sha256": "sha256:" + strings.Repeat("a", 64),
		"plaintext_digest_sha256": "sha256:" + strings.Repeat("c", 64), "ciphertext_bytes": int64(1040), "plaintext_bytes": int64(1024),
	}
	for _, test := range []struct {
		name       string
		mutate     func(map[string]any)
		tamperSign bool
		wantErr    bool
	}{
		{name: "valid"},
		{name: "other owner", mutate: func(document map[string]any) { document["owner_digest"] = contract.Digest([]byte("other")) }, wantErr: true},
		{name: "expired", mutate: func(document map[string]any) {
			document["issued_at"] = now.Add(-10 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
			document["expires_at"] = now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
		}, wantErr: true},
		{name: "zero lifetime", mutate: func(document map[string]any) { document["expires_at"] = document["issued_at"] }, wantErr: true},
		{name: "tampered signature", tamperSign: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := map[string]any{
				"schema": AuthorizationSchema, "authorization_id": "11111111-1111-4111-8111-111111111111", "owner_digest": owner,
				"sealed_record_sha256": declaration["sealed_record_sha256"], "kind": declaration["kind"], "sealed_reference": declaration["sealed_reference"],
				"ciphertext_sha256": declaration["ciphertext_digest_sha256"], "plaintext_sha256": declaration["plaintext_digest_sha256"], "ciphertext_bytes": declaration["ciphertext_bytes"], "plaintext_bytes": declaration["plaintext_bytes"],
				"issued_at": now.Format("2006-01-02T15:04:05.000000Z"), "expires_at": now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": "staging-test",
			}
			if test.mutate != nil {
				test.mutate(document)
			}
			unsigned, _ := contract.CanonicalJSON(document)
			signature := ed25519.Sign(private, unsigned)
			if test.tamperSign {
				signature[0] ^= 0xff
			}
			document["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(signature)}
			raw, _ := contract.CanonicalJSON(document)
			raw = append(raw, '\n') // Normal framework JSON need not use the wire's canonical key order/spacing.
			client := &PolarisClient{
				Origin: "https://polaris.example", BearerToken: []byte("token"), SigningKeyID: "staging-test", SigningPublicKey: public, Now: func() time.Time { return now },
				Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.Header.Get("Authorization") != "Bearer token" || request.URL.Path != StagingAuthorizationPath {
						t.Fatal("authorization request omitted bearer binding or used wrong path")
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
				})},
			}
			_, err := client.Authorize(context.Background(), declaration, owner)
			if (err != nil) != test.wantErr {
				t.Fatalf("Authorize error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestPolarisBindingRequiresExactProfileAndOwner(t *testing.T) {
	owner := contract.Digest([]byte("owner"))
	for _, document := range []map[string]any{
		{"schema": BindingSchema, "owner_digest": owner, "profile_id": contract.ProfileID},
		{"schema": BindingSchema, "owner_digest": "customer-id", "profile_id": contract.ProfileID},
		{"schema": BindingSchema, "owner_digest": owner, "profile_id": "different-profile"},
		{"schema": BindingSchema, "owner_digest": owner, "profile_id": contract.ProfileID, "extra": true},
	} {
		raw, _ := contract.CanonicalJSON(document)
		client := &PolarisClient{
			Origin: "https://polaris.example", BearerToken: []byte("token"), SigningKeyID: "key", SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
			Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})},
		}
		binding, err := client.Binding(context.Background())
		valid := document["owner_digest"] == owner && document["profile_id"] == contract.ProfileID && len(document) == 3
		if valid && (err != nil || binding.OwnerDigest != owner) {
			t.Fatalf("valid binding rejected: %v", err)
		}
		if !valid && err == nil {
			t.Fatalf("invalid binding accepted: %#v", document)
		}
	}
}

func TestStageRejectsIncompleteTrustClientsBeforeUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	_ = os.WriteFile(path, []byte("four"), 0o600)
	_, err := Stage(context.Background(), Options{InputPath: path, Kind: "input", Bucket: "bucket", Prefix: "tenant", GCS: &GCSClient{}, Polaris: &PolarisClient{}, KBS: &KBSClient{}})
	if err == nil {
		t.Fatal("incomplete trust clients were accepted")
	}
}

func TestOpenPlaintextRejectsSymlinkAndEmptyFile(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := openPlaintext(empty); err == nil {
		t.Fatal("empty input was accepted")
	}
	link := filepath.Join(directory, "link")
	_ = os.Symlink(empty, link)
	if _, err := openPlaintext(link); err == nil {
		t.Fatal("symlink input was accepted")
	}
}

func TestProtectedCredentialRejectsSymlinkAndExposedSecret(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(directory, "token")
	if err := os.WriteFile(private, []byte("token-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readSecureCredentialWithin(private, true, directory); err != nil || string(raw) != "token-value" {
		t.Fatalf("private credential rejected: %v", err)
	}
	link := filepath.Join(directory, "token-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureCredentialWithin(link, true, directory); err == nil {
		t.Fatal("symlinked secret credential was accepted")
	}
	if err := os.Chmod(private, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureCredentialWithin(private, true, directory); err == nil {
		t.Fatal("group-readable secret credential was accepted")
	}
	writable := filepath.Join(directory, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o770); err != nil {
		t.Fatal(err)
	}
	writableToken := filepath.Join(writable, "token")
	if err := os.WriteFile(writableToken, []byte("token-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureCredentialWithin(writableToken, true, directory); err == nil {
		t.Fatal("credential below a writable ancestor was accepted")
	}
}

func TestGcloudTokenSourceRejectsFinalSymlinkAndWritableExecutable(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "gcloud-real")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "gcloud")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (GcloudTokenSource{Path: link}).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatal("symlinked gcloud executable was accepted")
	}
	if err := os.Chmod(executable, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := (GcloudTokenSource{Path: executable}).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatal("writable gcloud executable was accepted")
	}
}

func decryptFixture(t *testing.T, framed []byte, record map[string]any) []byte {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(record["key_base64"].(string))
	noncePrefix, _ := base64.StdEncoding.DecodeString(record["nonce_prefix_base64"].(string))
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	reader := bytes.NewReader(framed)
	output := bytes.Buffer{}
	plainBytes, _ := strconvNumber(record["plaintext_bytes"])
	for index := uint32(0); reader.Len() > 0; index++ {
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 12)
		copy(nonce, noncePrefix)
		binary.BigEndian.PutUint32(nonce[8:], index)
		aad, _ := contract.CanonicalJSON(map[string]any{"kind": record["kind"], "plaintext_sha256": record["plaintext_sha256"], "plaintext_bytes": plainBytes, "chunk_index": index})
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(plaintext)
	}
	return output.Bytes()
}

func strconvNumber(value any) (int64, error) {
	switch typed := value.(type) {
	case json.Number:
		var result int64
		_, err := fmt.Sscan(string(typed), &result)
		return result, err
	case int64:
		return typed, nil
	default:
		return 0, io.ErrUnexpectedEOF
	}
}

func lenNumber(value []byte) string { return fmt.Sprint(len(value)) }

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFixtureDigestsAreStable(t *testing.T) {
	fixture := []float32{1, -2, 3.5, 4}
	buffer := bytes.Buffer{}
	_ = binary.Write(&buffer, binary.LittleEndian, fixture)
	digest := sha256.Sum256(buffer.Bytes())
	if hex.EncodeToString(digest[:]) != "c9e7f1cef2b38dec871fb2629a19e3c622d49ac96fa567d28bc8944e7ef1b028" {
		t.Fatal("terminal proof fixture input digest changed")
	}
}
