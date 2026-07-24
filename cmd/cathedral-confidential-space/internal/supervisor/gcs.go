package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	gcsProductionOrigin = "https://storage.googleapis.com"
	metadataTokenURL    = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

var (
	ErrGCSObjectAbsent       = errors.New("GCS object is absent")
	errGCSWriteUncertain     = errors.New("GCS write outcome is uncertain")
	errGCSPreconditionFailed = errors.New("GCS write precondition failed")
)

type OAuthTokenSource interface {
	Token(context.Context) (string, error)
}

type MetadataTokenSource struct {
	Client *http.Client
	lock   sync.Mutex
	token  string
	expiry time.Time
}

func (source *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	if source == nil || source.Client == nil {
		return "", errors.New("metadata token source is not configured")
	}
	source.lock.Lock()
	defer source.lock.Unlock()
	if source.token != "" && time.Until(source.expiry) > time.Minute {
		return source.token, nil
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := source.Client.Do(request)
	if err != nil {
		return "", errors.New("workload identity token metadata request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("workload identity token metadata response is untrusted")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 64*1024 {
		return "", errors.New("workload identity token metadata response is invalid")
	}
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "access_token", "expires_in", "token_type") || document["token_type"] != "Bearer" {
		return "", errors.New("workload identity token metadata schema is invalid")
	}
	token, tokenOK := document["access_token"].(string)
	expiresNumber, numberOK := document["expires_in"].(json.Number)
	expires, parseErr := strconv.ParseInt(string(expiresNumber), 10, 64)
	if !tokenOK || token == "" || len(token) > 16384 || !numberOK || parseErr != nil || expires < 120 || expires > 24*60*60 {
		return "", errors.New("workload identity token metadata values are invalid")
	}
	source.token = token
	source.expiry = time.Now().Add(time.Duration(expires) * time.Second)
	return token, nil
}

type GCSClient struct {
	Bucket string
	Prefix string
	Client *http.Client
	Tokens OAuthTokenSource
	Origin string
}

func NewProductionGCSClient(bucket, prefix string, client *http.Client, tokens OAuthTokenSource) (*GCSClient, error) {
	store := &GCSClient{Bucket: bucket, Prefix: strings.Trim(prefix, "/"), Client: client, Tokens: tokens, Origin: gcsProductionOrigin}
	if err := store.validate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *GCSClient) validate() error {
	if store == nil || store.Client == nil || store.Tokens == nil || store.Origin == "" || store.Bucket == "" || store.Prefix == "" || strings.ContainsAny(store.Bucket, "/?#@") || strings.Contains(store.Prefix, "..") || strings.HasPrefix(store.Prefix, "/") {
		return errors.New("GCS control store is not fail-closed configured")
	}
	origin, err := url.Parse(store.Origin)
	if err != nil || origin.Scheme != "https" && !strings.HasPrefix(store.Origin, "http://127.0.0.1:") || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.User != nil {
		return errors.New("GCS API origin is invalid")
	}
	return nil
}

func (store *GCSClient) object(relative string) (string, error) {
	if relative == "" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "..") || strings.ContainsAny(relative, "?#\x00") {
		return "", errors.New("GCS object path is invalid")
	}
	return store.Prefix + "/" + relative, nil
}

func (store *GCSClient) PutIfAbsent(ctx context.Context, reference string, value []byte, digest string) error {
	prefix := "gs://" + store.Bucket + "/" + store.Prefix + "/"
	if !strings.HasPrefix(reference, prefix) || !contract.ValidDigest(digest) || contract.Digest(value) != digest {
		return errors.New("immutable GCS output reference or digest is invalid")
	}
	object := strings.TrimPrefix(reference, "gs://"+store.Bucket+"/")
	_, err := store.put(ctx, object, value, "application/octet-stream", "0")
	if errors.Is(err, errGCSWriteUncertain) || errors.Is(err, errGCSPreconditionFailed) {
		_, err = store.recoverExact(ctx, object, value)
	}
	return err
}

func (store *GCSClient) PutCreateOnly(ctx context.Context, relative string, value []byte, contentType string) (string, error) {
	object, err := store.object(relative)
	if err != nil {
		return "", err
	}
	generation, err := store.put(ctx, object, value, contentType, "0")
	if errors.Is(err, errGCSWriteUncertain) || errors.Is(err, errGCSPreconditionFailed) {
		return store.recoverExact(ctx, object, value)
	}
	return generation, err
}

func (store *GCSClient) PutCAS(ctx context.Context, relative string, value []byte, generation string) (string, error) {
	if generation == "" {
		return "", errors.New("GCS CAS generation is absent")
	}
	object, err := store.object(relative)
	if err != nil {
		return "", err
	}
	writtenGeneration, err := store.put(ctx, object, value, "application/json", generation)
	if errors.Is(err, errGCSWriteUncertain) || errors.Is(err, errGCSPreconditionFailed) {
		return store.recoverExact(ctx, object, value)
	}
	return writtenGeneration, err
}

func (store *GCSClient) put(ctx context.Context, object string, value []byte, contentType, generation string) (string, error) {
	if err := store.validate(); err != nil || len(value) == 0 || len(value) > contract.MaxDocumentBytes || contentType == "" {
		return "", errors.New("GCS immutable object payload is invalid")
	}
	token, err := store.Tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	query := url.Values{"uploadType": {"media"}, "name": {object}, "ifGenerationMatch": {generation}}
	endpoint := store.Origin + "/upload/storage/v1/b/" + url.PathEscape(store.Bucket) + "/o?" + query.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(value))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-Goog-Content-SHA256", strings.TrimPrefix(contract.Digest(value), "sha256:"))
	response, err := store.Client.Do(request)
	if err != nil {
		return "", errGCSWriteUncertain
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return "", errGCSPreconditionFailed
	}
	if response.StatusCode != http.StatusOK {
		return "", errors.New("GCS conditional upload was rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 {
		return "", errGCSWriteUncertain
	}
	var metadata struct {
		Generation string `json:"generation"`
		Name       string `json:"name"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.Name != object || metadata.Generation == "" {
		return "", errGCSWriteUncertain
	}
	if _, err := strconv.ParseUint(metadata.Generation, 10, 64); err != nil {
		return "", errGCSWriteUncertain
	}
	return metadata.Generation, nil
}

func (store *GCSClient) recoverExact(ctx context.Context, object string, expected []byte) (string, error) {
	generation, err := store.objectGeneration(ctx, object)
	if err != nil {
		return "", errors.New("GCS conditional write could not be recovered")
	}
	reader, err := store.openAbsoluteGeneration(ctx, object, generation)
	if err != nil {
		return "", errors.New("GCS conditional write could not be recovered")
	}
	defer reader.Close()
	observed, err := io.ReadAll(io.LimitReader(reader, int64(len(expected))+1))
	if err != nil || !bytes.Equal(observed, expected) {
		return "", errors.New("GCS conditional write conflicts with the committed object")
	}
	return generation, nil
}

func (store *GCSClient) objectGeneration(ctx context.Context, object string) (string, error) {
	if err := store.validate(); err != nil || object == "" || strings.HasPrefix(object, "/") || strings.Contains(object, "..") || strings.ContainsAny(object, "?#\x00") {
		return "", errors.New("GCS metadata object path is invalid")
	}
	token, err := store.Tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	endpoint := store.Origin + "/storage/v1/b/" + url.PathEscape(store.Bucket) + "/o/" + url.PathEscape(object) + "?fields=name,generation"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := store.Client.Do(request)
	if err != nil {
		return "", errors.New("GCS object metadata read failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("GCS object metadata read was rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	var metadata struct {
		Generation string `json:"generation"`
		Name       string `json:"name"`
	}
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || json.Unmarshal(raw, &metadata) != nil || metadata.Name != object {
		return "", errors.New("GCS object metadata is invalid")
	}
	if _, err := strconv.ParseUint(metadata.Generation, 10, 64); err != nil {
		return "", errors.New("GCS object generation is invalid")
	}
	return metadata.Generation, nil
}

func (store *GCSClient) Get(ctx context.Context, relative string) ([]byte, error) {
	reader, err := store.openRelative(ctx, relative)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, contract.MaxDocumentBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > contract.MaxDocumentBytes {
		return nil, errors.New("GCS object is empty or oversized")
	}
	return raw, nil
}

func (store *GCSClient) Open(ctx context.Context, reference string) (io.ReadCloser, error) {
	prefix := "gs://" + store.Bucket + "/"
	if !strings.HasPrefix(reference, prefix) || !strings.Contains(strings.TrimPrefix(reference, prefix), "/sealed-inputs/sha256/") {
		return nil, errors.New("GCS sealed reference is outside the immutable input namespace")
	}
	object := strings.TrimPrefix(reference, prefix)
	if strings.Contains(object, "..") || strings.ContainsAny(object, "?#\x00") || !strings.HasSuffix(object, ".ccgpu") {
		return nil, errors.New("GCS sealed reference is not a content-addressed object")
	}
	return store.openAbsolute(ctx, object)
}

func (store *GCSClient) openRelative(ctx context.Context, relative string) (io.ReadCloser, error) {
	if err := store.validate(); err != nil {
		return nil, err
	}
	object, err := store.object(relative)
	if err != nil {
		return nil, err
	}
	return store.openAbsolute(ctx, object)
}

func (store *GCSClient) openAbsolute(ctx context.Context, object string) (io.ReadCloser, error) {
	return store.openAbsoluteGeneration(ctx, object, "")
}

func (store *GCSClient) openAbsoluteGeneration(ctx context.Context, object, generation string) (io.ReadCloser, error) {
	if err := store.validate(); err != nil || object == "" || strings.HasPrefix(object, "/") || strings.Contains(object, "..") || strings.ContainsAny(object, "?#\x00") {
		return nil, errors.New("GCS absolute object path is invalid")
	}
	if generation != "" {
		if _, err := strconv.ParseUint(generation, 10, 64); err != nil {
			return nil, errors.New("GCS absolute object generation is invalid")
		}
	}
	token, err := store.Tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	query := url.Values{"alt": {"media"}}
	if generation != "" {
		query.Set("generation", generation)
	}
	endpoint := store.Origin + "/storage/v1/b/" + url.PathEscape(store.Bucket) + "/o/" + url.PathEscape(object) + "?" + query.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := store.Client.Do(request)
	if err != nil {
		return nil, errors.New("GCS object read failed")
	}
	if response.StatusCode == http.StatusNotFound {
		_ = response.Body.Close()
		return nil, ErrGCSObjectAbsent
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, errors.New("GCS object read was rejected")
	}
	return response.Body, nil
}

type GCSControlStore struct {
	GCS              *GCSClient
	JobID            string
	AttemptID        string
	JobContextDigest string
	PollInterval     time.Duration
	Now              func() time.Time
	statusLock       sync.Mutex
	statusGeneration string
	statusRevision   int64
}

func (store *GCSControlStore) now() string {
	clock := store.Now
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func (store *GCSControlStore) base(schema string) map[string]any {
	return map[string]any{"schema": schema, "job_id": store.JobID, "attempt_id": store.AttemptID, "job_context_digest": store.JobContextDigest}
}

func (store *GCSControlStore) validate() error {
	if store == nil || store.GCS == nil || store.JobID == "" || store.AttemptID == "" || !contract.ValidDigest(store.JobContextDigest) || store.PollInterval < 100*time.Millisecond || store.PollInterval > time.Minute {
		return errors.New("GCS control contract is invalid")
	}
	return store.GCS.validate()
}

func (store *GCSControlStore) PublishAdmission(ctx context.Context, raw []byte) error {
	if err := store.validate(); err != nil {
		return err
	}
	value, err := contract.StrictJSON(raw)
	evidence, ok := value.(map[string]any)
	proof, proofOK := evidence["channel_proof"].(map[string]any)
	if err != nil || !ok || !proofOK || !contract.ValidDigest(proof["tls_ekm_sha256"]) {
		return errors.New("admission evidence cannot be wrapped for GCS")
	}
	document := store.base("cathedral_cc_gpu_admission_control_v1")
	document["evidence"] = evidence
	document["evidence_sha256"] = contract.Digest(raw)
	document["tls_ekm_sha256"] = proof["tls_ekm_sha256"]
	document["published_at"] = store.now()
	encoded, _ := contract.CanonicalJSON(document)
	_, err = store.GCS.PutCreateOnly(ctx, "admission.json", encoded, "application/json")
	return err
}

func (store *GCSControlStore) PublishRelease(ctx context.Context, requestRaw, ackRaw, policyRaw []byte) error {
	requestValue, requestErr := contract.StrictJSON(requestRaw)
	ackValue, ackErr := contract.StrictJSON(ackRaw)
	policyValue, policyErr := contract.StrictJSON(policyRaw)
	if requestErr != nil || ackErr != nil || policyErr != nil {
		return errors.New("release request or ack cannot be wrapped for GCS")
	}
	document := store.base("cathedral_cc_gpu_release_control_v1")
	document["release_request"] = requestValue
	document["release_request_sha256"] = contract.Digest(requestRaw)
	document["release_ack"] = ackValue
	document["release_ack_sha256"] = contract.Digest(ackRaw)
	document["release_policy"] = policyValue
	document["release_policy_sha256"] = contract.Digest(policyRaw)
	document["published_at"] = store.now()
	encoded, _ := contract.CanonicalJSON(document)
	_, err := store.GCS.PutCreateOnly(ctx, "release.json", encoded, "application/json")
	return err
}

func (store *GCSControlStore) PublishStatus(ctx context.Context, state string, detail map[string]any) error {
	allowed := map[string]bool{"running": true, "finalizing": true, "cancelled": true, "failed": true}
	if !allowed[state] || detail == nil {
		return errors.New("guest status state or detail is invalid")
	}
	store.statusLock.Lock()
	defer store.statusLock.Unlock()
	store.statusRevision++
	document := store.base("cathedral_cc_gpu_guest_status_v1")
	document["state"] = state
	document["revision"] = store.statusRevision
	document["detail"] = detail
	document["updated_at"] = store.now()
	encoded, _ := contract.CanonicalJSON(document)
	var generation string
	var err error
	if store.statusGeneration == "" {
		generation, err = store.GCS.PutCreateOnly(ctx, "guest-status.json", encoded, "application/json")
	} else {
		generation, err = store.GCS.PutCAS(ctx, "guest-status.json", encoded, store.statusGeneration)
	}
	if err != nil {
		return err
	}
	store.statusGeneration = generation
	return nil
}

func (store *GCSControlStore) WaitFinalize(ctx context.Context, result, manifest string) (Finalize, error) {
	if !contract.ValidDigest(result) || !contract.ValidDigest(manifest) {
		return Finalize{}, errors.New("finalize result bindings are invalid")
	}
	ticker := time.NewTicker(store.PollInterval)
	defer ticker.Stop()
	for {
		raw, err := store.GCS.Get(ctx, "finalize.json")
		if err == nil {
			value, parseErr := contract.StrictJSON(raw)
			document, ok := value.(map[string]any)
			if parseErr != nil || !ok || !contract.ExactKeys(document, "schema", "job_id", "attempt_id", "job_context_digest", "result_sha256", "artifact_manifest_sha256", "challenge_base64", "challenge_sha256", "finalize_sha256", "published_at") || document["schema"] != "cathedral_cc_gpu_finalize_control_v1" || document["job_id"] != store.JobID || document["attempt_id"] != store.AttemptID || document["job_context_digest"] != store.JobContextDigest || document["result_sha256"] != result || document["artifact_manifest_sha256"] != manifest || !contract.ValidDigest(document["challenge_sha256"]) || !contract.ValidDigest(document["finalize_sha256"]) {
				return Finalize{}, errors.New("immutable finalize control object is invalid or mismatched")
			}
			challengeText, textOK := document["challenge_base64"].(string)
			challenge, decodeErr := base64.StdEncoding.Strict().DecodeString(challengeText)
			if !textOK || decodeErr != nil || base64.StdEncoding.EncodeToString(challenge) != challengeText || contract.Digest(challenge) != document["challenge_sha256"] {
				return Finalize{}, errors.New("immutable finalize challenge is invalid")
			}
			return Finalize{Challenge: challenge, Digest: document["finalize_sha256"].(string)}, nil
		}
		select {
		case <-ctx.Done():
			return Finalize{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (store *GCSControlStore) PublishCompletion(ctx context.Context, completion CompletionControl) error {
	value, err := contract.StrictJSON(completion.Evidence)
	evidence, ok := value.(map[string]any)
	manifestValue, manifestErr := contract.StrictJSON(completion.ManifestCanonical)
	manifest, manifestOK := manifestValue.(map[string]any)
	proof, proofOK := evidence["channel_proof"].(map[string]any)
	if err != nil || !ok || manifestErr != nil || !manifestOK || !proofOK || !contract.ValidDigest(proof["tls_ekm_sha256"]) || !contract.ValidDigest(completion.ResultSHA256) || !contract.ValidDigest(completion.FinalizeSHA256) {
		return errors.New("completion evidence cannot be wrapped for GCS")
	}
	document := store.base("cathedral_cc_gpu_completion_control_v1")
	document["evidence"] = evidence
	document["evidence_sha256"] = contract.Digest(completion.Evidence)
	document["result_sha256"] = completion.ResultSHA256
	document["artifact_manifest_sha256"] = contract.Digest(completion.ManifestCanonical)
	document["output_manifest"] = manifest
	document["output_manifest_sha256"] = contract.Digest(completion.ManifestCanonical)
	document["tls_ekm_sha256"] = proof["tls_ekm_sha256"]
	document["finalize_sha256"] = completion.FinalizeSHA256
	document["published_at"] = store.now()
	encoded, _ := contract.CanonicalJSON(document)
	_, err = store.GCS.PutCreateOnly(ctx, "completion.json", encoded, "application/json")
	return err
}

func (store *GCSControlStore) PublishCleanup(ctx context.Context, raw []byte) error {
	value, err := contract.StrictJSON(raw)
	cleanup, ok := value.(map[string]any)
	if err != nil || !ok {
		return errors.New("cleanup evidence cannot be wrapped for GCS")
	}
	document := store.base("cathedral_cc_gpu_cleanup_control_v1")
	document["cleanup"] = cleanup
	document["cleanup_sha256"] = contract.Digest(raw)
	document["published_at"] = store.now()
	encoded, _ := contract.CanonicalJSON(document)
	_, err = store.GCS.PutCreateOnly(ctx, "cleanup.json", encoded, "application/json")
	return err
}

func (store *GCSControlStore) Cancellation(ctx context.Context) <-chan struct{} {
	cancelled := make(chan struct{})
	go func() {
		ticker := time.NewTicker(store.PollInterval)
		defer ticker.Stop()
		for {
			raw, err := store.GCS.Get(ctx, "cancel.json")
			if err == nil {
				value, parseErr := contract.StrictJSON(raw)
				document, ok := value.(map[string]any)
				if parseErr == nil && ok && contract.ExactKeys(document, "schema", "job_id", "attempt_id", "job_context_digest", "requested_at") && document["schema"] == "cathedral_cc_gpu_cancel_control_v1" && document["job_id"] == store.JobID && document["attempt_id"] == store.AttemptID && document["job_context_digest"] == store.JobContextDigest {
					close(cancelled)
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return cancelled
}
