package staging

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	SealedRecordSchema          = "cathedral_cc_gpu_kbs_sealed_input_record_v1"
	SealedStageRequestSchema    = "cathedral_cc_gpu_kbs_sealed_input_stage_request_v1"
	SealedRegistrationAckSchema = "cathedral_cc_gpu_kbs_sealed_input_staging_ack_v1"
	BindingSchema               = "cathedral_cc_gpu_staging_binding_v1"
	AuthorizationRequestSchema  = "cathedral_cc_gpu_staging_authorization_request_v1"
	AuthorizationSchema         = "cathedral_cc_gpu_kbs_sealed_input_stage_authorization_v1"
	ChunkBytes                  = 4 * 1024 * 1024
	GCSOrigin                   = "https://storage.googleapis.com"
	StagingBindingPath          = "/v1/workers/cc-gpu/staging-binding"
	StagingAuthorizationPath    = "/v1/workers/cc-gpu/staging-authorization"
)

type TokenSource interface {
	Token(context.Context) (string, error)
}

type GcloudTokenSource struct {
	Path string
}

func (source GcloudTokenSource) Token(ctx context.Context) (string, error) {
	if !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path {
		return "", errors.New("gcloud executable path must be absolute and clean")
	}
	// The local Cloud SDK and its module tree remain an operator-trusted input;
	// this subprocess is not part of the attested guest. Refuse a final symlink
	// or writable executable so the exact CLI entrypoint is at least explicit.
	info, err := os.Lstat(source.Path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("gcloud executable is absent, symlinked, or writable")
	}
	command := exec.CommandContext(ctx, source.Path, "auth", "application-default", "print-access-token")
	command.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	var output bytes.Buffer
	command.Stdout = &limitedWriter{writer: &output, remaining: 16 * 1024}
	command.Stderr = &limitedWriter{writer: io.Discard, remaining: 64 * 1024}
	if err := command.Run(); err != nil {
		return "", errors.New("gcloud application-default access token request failed")
	}
	token := strings.TrimSpace(output.String())
	if token == "" || len(token) > 16*1024 || strings.ContainsAny(token, " \r\n\t") {
		return "", errors.New("gcloud returned an invalid access token")
	}
	return token, nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	if len(value) > writer.remaining {
		return 0, errors.New("subprocess output exceeds bound")
	}
	count, err := writer.writer.Write(value)
	writer.remaining -= count
	if err != nil {
		return count, err
	}
	return original, nil
}

type GCSClient struct {
	Origin string
	Client *http.Client
	Tokens TokenSource
}

func NewProductionGCSClient(tokens TokenSource) *GCSClient {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	return &GCSClient{Origin: GCSOrigin, Client: &http.Client{Transport: transport, Timeout: 2 * time.Hour, CheckRedirect: noRedirect}, Tokens: tokens}
}

func (client *GCSClient) UploadIfAbsent(ctx context.Context, bucket, object, path, digest string, size int64) error {
	if err := client.validate(); err != nil || !validBucketObject(bucket, object) || !contract.ValidDigest(digest) || size < 1 || size > contract.MaxProtectedCiphertextBytes {
		return errors.New("GCS immutable upload parameters are invalid")
	}
	token, err := client.Tokens.Token(ctx)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("sealed ciphertext could not be reopened")
	}
	defer file.Close()
	query := url.Values{"uploadType": {"media"}, "name": {object}, "ifGenerationMatch": {"0"}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.Origin+"/upload/storage/v1/b/"+url.PathEscape(bucket)+"/o?"+query.Encode(), file)
	request.ContentLength = size
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Goog-Content-SHA256", strings.TrimPrefix(digest, "sha256:"))
	response, err := client.Client.Do(request)
	if err != nil {
		if verifyErr := client.verifyExisting(ctx, token, bucket, object, digest, size); verifyErr == nil {
			return nil
		}
		return errors.New("GCS immutable upload failed and no exact committed object was recoverable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return client.verifyExisting(ctx, token, bucket, object, digest, size)
	}
	if response.StatusCode != http.StatusOK {
		if verifyErr := client.verifyExisting(ctx, token, bucket, object, digest, size); verifyErr == nil {
			return nil
		}
		return errors.New("GCS immutable upload was rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	var metadata struct {
		Name       string `json:"name"`
		Generation string `json:"generation"`
		Size       string `json:"size"`
	}
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || json.Unmarshal(raw, &metadata) != nil {
		if verifyErr := client.verifyExisting(ctx, token, bucket, object, digest, size); verifyErr == nil {
			return nil
		}
		return errors.New("GCS upload metadata is invalid and no exact committed object was recoverable")
	}
	parsedSize, parseSizeErr := strconv.ParseInt(metadata.Size, 10, 64)
	if metadata.Name != object || metadata.Generation == "" || parseSizeErr != nil || parsedSize != size {
		if verifyErr := client.verifyExisting(ctx, token, bucket, object, digest, size); verifyErr == nil {
			return nil
		}
		return errors.New("GCS upload metadata does not bind the immutable object")
	}
	if _, err := strconv.ParseUint(metadata.Generation, 10, 64); err != nil {
		if verifyErr := client.verifyExisting(ctx, token, bucket, object, digest, size); verifyErr == nil {
			return nil
		}
		return errors.New("GCS upload generation is invalid")
	}
	return client.verifyExisting(ctx, token, bucket, object, digest, size)
}

func (client *GCSClient) verifyExisting(ctx context.Context, token, bucket, object, digest string, size int64) error {
	endpoint := client.Origin + "/storage/v1/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(object) + "?alt=media"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Client.Do(request)
	if err != nil {
		return errors.New("existing GCS object could not be verified")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("content-addressed GCS object exists but is unreadable")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(response.Body, size+1))
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if err != nil || count != size || actual != digest {
		return errors.New("content-addressed GCS object conflicts with expected ciphertext")
	}
	return nil
}

func (client *GCSClient) validate() error {
	if client == nil || client.Client == nil || client.Tokens == nil {
		return errors.New("GCS client is incomplete")
	}
	parsed, err := url.Parse(client.Origin)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1") {
		return errors.New("GCS origin is invalid")
	}
	return nil
}

type KBSClient struct {
	Origin           string
	Client           *http.Client
	SigningKeyID     string
	SigningPublicKey ed25519.PublicKey
	Now              func() time.Time
}

func NewProductionKBSClient(origin, serverName, rootCAPath, signingKeyID, signingPublicKeyBase64 string) (*KBSClient, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || serverName == "" {
		return nil, errors.New("KBS server-auth TLS origin is invalid")
	}
	rootRaw, err := readSecureCredential(rootCAPath, false)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootRaw) {
		return nil, errors.New("KBS root CA is invalid")
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(signingPublicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(publicKey) != signingPublicKeyBase64 || signingKeyID == "" {
		return nil, errors.New("trusted KBS registration signing identity is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName}, ForceAttemptHTTP2: true}
	return &KBSClient{Origin: origin, Client: &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: noRedirect}, SigningKeyID: signingKeyID, SigningPublicKey: ed25519.PublicKey(publicKey)}, nil
}

func (client *KBSClient) validate() error {
	if client == nil || client.Client == nil || client.SigningKeyID == "" || len(client.SigningPublicKey) != ed25519.PublicKeySize {
		return errors.New("KBS registration client is incomplete")
	}
	parsed, err := url.Parse(client.Origin)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1") {
		return errors.New("KBS registration origin is invalid")
	}
	return nil
}

func (client *KBSClient) RegisterSealed(ctx context.Context, record, authorization []byte, expectedReference, expectedCiphertextDigest, expectedOwnerDigest string) (string, error) {
	if err := client.validate(); err != nil {
		return "", err
	}
	recordValue, recordErr := contract.StrictJSON(record)
	recordDocument, recordOK := recordValue.(map[string]any)
	authorizationValue, authorizationErr := contract.StrictJSON(authorization)
	authorizationDocument, authorizationOK := authorizationValue.(map[string]any)
	if recordErr != nil || authorizationErr != nil || !recordOK || !authorizationOK {
		return "", errors.New("KBS staged record or authorization is invalid")
	}
	requestRaw, err := contract.CanonicalJSON(map[string]any{"schema": SealedStageRequestSchema, "sealed_record": recordDocument, "authorization": authorizationDocument})
	if err != nil || len(requestRaw) > contract.MaxDocumentBytes {
		return "", errors.New("KBS staged record request is invalid")
	}
	defer zero(requestRaw)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.Origin+"/v1/staging/sealed-inputs", bytes.NewReader(requestRaw))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Client.Do(request)
	if err != nil {
		return "", errors.New("KBS sealed-input server-auth TLS registration failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return "", errors.New("KBS sealed-input registration was rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxDocumentBytes+1))
	value, parseErr := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || parseErr != nil || !ok || len(raw) == 0 || len(raw) > contract.MaxDocumentBytes || !contract.ExactKeys(document, "schema", "sealed_record_sha256", "owner_digest", "sealed_reference", "ciphertext_sha256", "staging_authorization_sha256", "registered_at", "signing_key_id", "signature") || document["schema"] != SealedRegistrationAckSchema || document["sealed_reference"] != expectedReference || document["ciphertext_sha256"] != expectedCiphertextDigest || document["owner_digest"] != expectedOwnerDigest || document["staging_authorization_sha256"] != contract.Digest(authorization) || document["signing_key_id"] != client.SigningKeyID || !contract.ValidDigest(document["sealed_record_sha256"]) || !contract.ValidDigest(document["owner_digest"]) {
		return "", errors.New("KBS sealed-input registration ack has an invalid exact binding")
	}
	registeredAt, timeErr := time.Parse("2006-01-02T15:04:05.000000Z", fmt.Sprint(document["registered_at"]))
	now := time.Now().UTC()
	if client.Now != nil {
		now = client.Now().UTC()
	}
	registeredText := fmt.Sprint(document["registered_at"])
	if timeErr != nil || registeredAt.Format("2006-01-02T15:04:05.000000Z") != registeredText || registeredAt.Before(now.Add(-5*time.Minute)) || registeredAt.After(now.Add(30*time.Second)) {
		return "", errors.New("KBS sealed-input registration ack is stale or future-dated")
	}
	signature, ok := document["signature"].(map[string]any)
	if !ok || !contract.ExactKeys(signature, "algorithm", "value_base64") || signature["algorithm"] != "ed25519" {
		return "", errors.New("KBS sealed-input registration signature is invalid")
	}
	signatureRaw, decodeErr := base64.StdEncoding.Strict().DecodeString(fmt.Sprint(signature["value_base64"]))
	unsigned := make(map[string]any, len(document)-1)
	for key, item := range document {
		if key != "signature" {
			unsigned[key] = item
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if decodeErr != nil || len(signatureRaw) != ed25519.SignatureSize || !ed25519.Verify(client.SigningPublicKey, canonical, signatureRaw) {
		return "", errors.New("KBS sealed-input registration signature verification failed")
	}
	digest := document["sealed_record_sha256"].(string)
	if digest != contract.Digest(record) {
		return "", errors.New("KBS sealed-input registration ack does not bind the submitted record")
	}
	return digest, nil
}

type PolarisClient struct {
	Origin           string
	Client           *http.Client
	BearerToken      []byte
	SigningKeyID     string
	SigningPublicKey ed25519.PublicKey
	Now              func() time.Time
}

type Binding struct {
	OwnerDigest string
}

func NewProductionPolarisClient(origin, tokenPath, signingKeyID, signingPublicKeyBase64 string) (*PolarisClient, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, errors.New("Polaris staging origin is invalid")
	}
	tokenRaw, err := readSecureCredential(tokenPath, true)
	if err != nil {
		return nil, err
	}
	defer zero(tokenRaw)
	tokenText := strings.TrimSpace(string(tokenRaw))
	if tokenText == "" || len(tokenText) > 16*1024 || strings.ContainsAny(tokenText, " \r\n\t") {
		return nil, errors.New("Polaris staging bearer token is invalid")
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(signingPublicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(publicKey) != signingPublicKeyBase64 || signingKeyID == "" {
		return nil, errors.New("trusted staging authority signing identity is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	return &PolarisClient{Origin: origin, Client: &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: noRedirect}, BearerToken: []byte(tokenText), SigningKeyID: signingKeyID, SigningPublicKey: ed25519.PublicKey(publicKey)}, nil
}

func (client *PolarisClient) Close() {
	if client != nil {
		zero(client.BearerToken)
		client.BearerToken = nil
	}
}

func (client *PolarisClient) validate() error {
	if client == nil || client.Client == nil || len(client.BearerToken) < 1 || len(client.BearerToken) > 16*1024 || client.SigningKeyID == "" || len(client.SigningPublicKey) != ed25519.PublicKeySize {
		return errors.New("Polaris staging client is incomplete")
	}
	parsed, err := url.Parse(client.Origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("Polaris staging origin is invalid")
	}
	return nil
}

func (client *PolarisClient) Binding(ctx context.Context) (*Binding, error) {
	if err := client.validate(); err != nil {
		return nil, err
	}
	raw, err := client.do(ctx, http.MethodGet, StagingBindingPath, nil)
	if err != nil {
		return nil, err
	}
	value, parseErr := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if parseErr != nil || !ok || !contract.ExactKeys(document, "schema", "owner_digest", "profile_id") || document["schema"] != BindingSchema || document["profile_id"] != contract.ProfileID || !contract.ValidDigest(document["owner_digest"]) {
		return nil, errors.New("Polaris staging binding is invalid")
	}
	return &Binding{OwnerDigest: document["owner_digest"].(string)}, nil
}

func (client *PolarisClient) Authorize(ctx context.Context, declaration map[string]any, expectedOwnerDigest string) ([]byte, error) {
	if err := client.validate(); err != nil {
		return nil, err
	}
	requestDocument := map[string]any{
		"schema": AuthorizationRequestSchema, "kind": declaration["kind"], "sealed_reference": declaration["sealed_reference"], "sealed_record_sha256": declaration["sealed_record_sha256"],
		"ciphertext_digest_sha256": declaration["ciphertext_digest_sha256"], "plaintext_digest_sha256": declaration["plaintext_digest_sha256"], "ciphertext_bytes": declaration["ciphertext_bytes"], "plaintext_bytes": declaration["plaintext_bytes"],
	}
	requestRaw, err := contract.CanonicalJSON(requestDocument)
	if err != nil {
		return nil, errors.New("Polaris staging authorization request is invalid")
	}
	raw, err := client.do(ctx, http.MethodPost, StagingAuthorizationPath, requestRaw)
	if err != nil {
		return nil, err
	}
	value, parseErr := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if parseErr != nil || !ok || !contract.ExactKeys(document, "schema", "authorization_id", "owner_digest", "sealed_record_sha256", "kind", "sealed_reference", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes", "issued_at", "expires_at", "signing_key_id", "signature") || document["schema"] != AuthorizationSchema || document["owner_digest"] != expectedOwnerDigest || document["sealed_record_sha256"] != declaration["sealed_record_sha256"] || document["kind"] != declaration["kind"] || document["sealed_reference"] != declaration["sealed_reference"] || document["ciphertext_sha256"] != declaration["ciphertext_digest_sha256"] || document["plaintext_sha256"] != declaration["plaintext_digest_sha256"] || !canonicalEqual(document["ciphertext_bytes"], declaration["ciphertext_bytes"]) || !canonicalEqual(document["plaintext_bytes"], declaration["plaintext_bytes"]) || document["signing_key_id"] != client.SigningKeyID || !contract.ValidDigest(document["owner_digest"]) || !contract.ValidDigest(document["sealed_record_sha256"]) || !contract.ValidUUID(document["authorization_id"]) {
		return nil, errors.New("Polaris staging authorization has an invalid exact binding")
	}
	issuedText, issuedOK := document["issued_at"].(string)
	issued, issuedErr := time.Parse("2006-01-02T15:04:05.000000Z", issuedText)
	expiresText, expiresOK := document["expires_at"].(string)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05.000000Z", expiresText)
	now := time.Now().UTC()
	if client.Now != nil {
		now = client.Now().UTC()
	}
	if !issuedOK || issuedErr != nil || issued.Format("2006-01-02T15:04:05.000000Z") != issuedText || !expiresOK || expiresErr != nil || expires.Format("2006-01-02T15:04:05.000000Z") != expiresText || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute || now.Before(issued.Add(-30*time.Second)) || now.After(expires.Add(30*time.Second)) {
		return nil, errors.New("Polaris staging authorization is stale, future, or overlong")
	}
	if err := verifySignature(document, client.SigningPublicKey); err != nil {
		return nil, err
	}
	canonical, err := contract.CanonicalJSON(document)
	if err != nil {
		return nil, errors.New("Polaris staging authorization could not be canonicalized")
	}
	return canonical, nil
}

func (client *PolarisClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	request, _ := http.NewRequestWithContext(ctx, method, client.Origin+path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+string(client.BearerToken))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Client.Do(request)
	if err != nil {
		return nil, errors.New("Polaris staging API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("Polaris staging API request was rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxDocumentBytes+1))
	if err != nil || len(raw) < 1 || len(raw) > contract.MaxDocumentBytes {
		return nil, errors.New("Polaris staging API response is invalid or oversized")
	}
	return raw, nil
}

type Options struct {
	InputPath string
	Kind      string
	Bucket    string
	Prefix    string
	TempDir   string
	GCS       *GCSClient
	Polaris   *PolarisClient
	KBS       *KBSClient
	Random    io.Reader
}

type Declaration struct {
	Kind                   string `json:"kind"`
	OwnerDigest            string `json:"-"` // Internal KBS binding; never part of the customer API declaration.
	SealedReference        string `json:"sealed_reference"`
	SealedRecordSHA256     string `json:"sealed_record_sha256"`
	CiphertextDigestSHA256 string `json:"ciphertext_digest_sha256"`
	PlaintextDigestSHA256  string `json:"plaintext_digest_sha256"`
	CiphertextBytes        int64  `json:"ciphertext_bytes"`
	PlaintextBytes         int64  `json:"plaintext_bytes"`
}

func Stage(ctx context.Context, options Options) (*Declaration, error) {
	if options.Kind != "input" && options.Kind != "model" || options.GCS == nil || options.Polaris == nil || options.KBS == nil || !validBucketObject(options.Bucket, strings.Trim(options.Prefix, "/")+"/sealed-inputs/sha256/x.ccgpu") {
		return nil, errors.New("protected-input staging options are invalid")
	}
	// Validate both remote clients, including the pinned KBS signing identity,
	// before encrypting, uploading, or registering any customer material.
	if err := options.GCS.validate(); err != nil {
		return nil, err
	}
	if err := options.KBS.validate(); err != nil {
		return nil, err
	}
	if err := options.Polaris.validate(); err != nil {
		return nil, err
	}
	binding, err := options.Polaris.Binding(ctx)
	if err != nil {
		return nil, err
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	file, err := openPlaintext(options.InputPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	plainDigest, plainBytes, err := hashPlaintext(file)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	noncePrefix := make([]byte, 8)
	if _, err := io.ReadFull(options.Random, key); err != nil {
		return nil, errors.New("protected-input data key generation failed")
	}
	defer zero(key)
	defer zero(noncePrefix)
	if _, err := io.ReadFull(options.Random, noncePrefix); err != nil {
		return nil, errors.New("protected-input nonce prefix generation failed")
	}
	temporary, err := os.CreateTemp(options.TempDir, ".cathedral-sealed-*.ccgpu")
	if err != nil {
		return nil, errors.New("temporary sealed-input file could not be created")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	cipherDigest, cipherBytes, err := encryptFile(file, temporary, options.Kind, plainDigest, plainBytes, key, noncePrefix)
	if closeErr := temporary.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	object := strings.Trim(options.Prefix, "/") + "/sealed-inputs/sha256/" + strings.TrimPrefix(cipherDigest, "sha256:") + ".ccgpu"
	reference := "gs://" + options.Bucket + "/" + object
	record := map[string]any{
		"schema": SealedRecordSchema, "kind": options.Kind, "owner_digest": binding.OwnerDigest, "sealed_reference": reference,
		"ciphertext_sha256": cipherDigest, "plaintext_sha256": plainDigest,
		"ciphertext_bytes": cipherBytes, "plaintext_bytes": plainBytes,
		"nonce_prefix_base64": base64.StdEncoding.EncodeToString(noncePrefix), "key_base64": base64.StdEncoding.EncodeToString(key),
	}
	recordRaw, _ := contract.CanonicalJSON(record)
	defer zero(recordRaw)
	declaration := map[string]any{
		"kind": options.Kind, "owner_digest": binding.OwnerDigest, "sealed_reference": reference, "sealed_record_sha256": contract.Digest(recordRaw),
		"ciphertext_digest_sha256": cipherDigest, "plaintext_digest_sha256": plainDigest, "ciphertext_bytes": cipherBytes, "plaintext_bytes": plainBytes,
	}
	authorization, err := options.Polaris.Authorize(ctx, declaration, binding.OwnerDigest)
	if err != nil {
		return nil, err
	}
	sealedRecordDigest, err := options.KBS.RegisterSealed(ctx, recordRaw, authorization, reference, cipherDigest, binding.OwnerDigest)
	if err != nil {
		return nil, err
	}
	// Publish ciphertext only after both the owner-bound Polaris authorization
	// and immutable KBS key record are accepted.  An authorization or KBS
	// failure therefore cannot leave a billable, unowned ciphertext object.
	if err := options.GCS.UploadIfAbsent(ctx, options.Bucket, object, temporaryPath, cipherDigest, cipherBytes); err != nil {
		return nil, err
	}
	return &Declaration{Kind: options.Kind, OwnerDigest: binding.OwnerDigest, SealedReference: reference, SealedRecordSHA256: sealedRecordDigest, CiphertextDigestSHA256: cipherDigest, PlaintextDigestSHA256: plainDigest, CiphertextBytes: cipherBytes, PlaintextBytes: plainBytes}, nil
}

func verifySignature(document map[string]any, publicKey ed25519.PublicKey) error {
	signature, ok := document["signature"].(map[string]any)
	if !ok || !contract.ExactKeys(signature, "algorithm", "value_base64") || signature["algorithm"] != "ed25519" {
		return errors.New("signed staging artifact signature is invalid")
	}
	signatureRaw, err := base64.StdEncoding.Strict().DecodeString(fmt.Sprint(signature["value_base64"]))
	unsigned := make(map[string]any, len(document)-1)
	for key, value := range document {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	canonical, canonicalErr := contract.CanonicalJSON(unsigned)
	if err != nil || canonicalErr != nil || len(signatureRaw) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signatureRaw) {
		return errors.New("signed staging artifact signature verification failed")
	}
	return nil
}

func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contract.CanonicalJSON(left)
	rightRaw, rightErr := contract.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func openPlaintext(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("protected-input path must be absolute and clean")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("protected input is not a regular non-symlink file")
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("protected input is unreadable")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("protected input descriptor is invalid")
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > contract.MaxVectorPlaintextBytes {
		_ = file.Close()
		return nil, errors.New("protected input is not a private bounded nonempty regular file")
	}
	return file, nil
}

func hashPlaintext(file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, contract.MaxVectorPlaintextBytes+1))
	if err != nil || count < 1 || count > contract.MaxVectorPlaintextBytes {
		return "", 0, errors.New("protected-input size or digest pass failed")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), count, nil
}

func encryptFile(input, output *os.File, kind, plainDigest string, plainBytes int64, key, noncePrefix []byte) (string, int64, error) {
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	plaintextHash := sha256.New()
	written := int64(0)
	buffer := make([]byte, ChunkBytes)
	for index := uint32(0); ; index++ {
		count, readErr := io.ReadFull(input, buffer)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return "", 0, errors.New("protected-input encryption read failed")
		}
		if count == 0 {
			break
		}
		_, _ = plaintextHash.Write(buffer[:count])
		nonce := make([]byte, 12)
		copy(nonce, noncePrefix)
		binary.BigEndian.PutUint32(nonce[8:], index)
		aad, _ := contract.CanonicalJSON(map[string]any{"kind": kind, "plaintext_sha256": plainDigest, "plaintext_bytes": plainBytes, "chunk_index": index})
		ciphertext := aead.Seal(nil, nonce, buffer[:count], aad)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(ciphertext)))
		for _, piece := range [][]byte{header, ciphertext} {
			if written > contract.MaxProtectedCiphertextBytes-int64(len(piece)) {
				zero(ciphertext)
				return "", 0, errors.New("framed protected ciphertext exceeds its bound")
			}
			if _, err := output.Write(piece); err != nil {
				zero(ciphertext)
				return "", 0, errors.New("framed protected ciphertext write failed")
			}
			_, _ = hash.Write(piece)
			written += int64(len(piece))
		}
		zero(ciphertext)
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
		if index == ^uint32(0) {
			return "", 0, errors.New("protected-input chunk counter exhausted")
		}
	}
	secondDigest := "sha256:" + hex.EncodeToString(plaintextHash.Sum(nil))
	if secondDigest != plainDigest {
		return "", 0, errors.New("protected input changed while it was being sealed")
	}
	if err := output.Sync(); err != nil {
		return "", 0, errors.New("sealed ciphertext could not be synced")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), written, nil
}

func validBucketObject(bucket, object string) bool {
	return bucket != "" && !strings.ContainsAny(bucket, "/?#@\x00") && object != "" && !strings.HasPrefix(object, "/") && !strings.Contains(object, "..") && !strings.ContainsAny(object, "?#\x00")
}

func readSecureCredential(path string, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("protected credential path must be absolute and clean")
	}
	if err := secureCredentialAncestors(path); err != nil {
		return nil, err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("protected credential path is absent or symlinked")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("protected credential descriptor is invalid")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("protected credential metadata is unreadable")
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || secret && (!ownerOK || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0) || info.Size() < 1 || info.Size() > 1024*1024 {
		return nil, errors.New("protected credential is writable, exposed, empty, or oversized")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) < 1 || len(raw) > 1024*1024 {
		return nil, errors.New("protected credential is unreadable or oversized")
	}
	return raw, nil
}

func secureCredentialAncestors(path string) error {
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return errors.New("protected credential has a symlinked or writable ancestor")
		}
		if ancestor == filepath.Dir(ancestor) {
			return nil
		}
	}
}

func noRedirect(*http.Request, []*http.Request) error { return errors.New("redirects are forbidden") }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
