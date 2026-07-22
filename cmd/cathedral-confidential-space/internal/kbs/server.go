package kbs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	ChallengeRequestSchema         = contract.KBSChallengeRequestSchema
	ChallengeSchema                = contract.KBSChallengeSchema
	ReleaseSubmitSchema            = contract.KBSReleaseSubmitSchema
	ReleaseResponseSchema          = contract.KBSReleaseResponseSchema
	ReleaseRequestSchema           = contract.KBSReleaseRequestSchema
	ReleaseAckSchema               = contract.KBSReleaseAckSchema
	CompletionStartSchema          = contract.KBSCompletionStartSchema
	CompletionAckSchema            = contract.KBSCompletionAckSchema
	JobRecordSchema                = "cathedral_cc_gpu_kbs_job_record_v1"
	SealedRecordSchema             = "cathedral_cc_gpu_kbs_sealed_input_record_v1"
	JobRegistrationSchema          = "cathedral_cc_gpu_kbs_job_registration_request_v1"
	JobRegistrationAckSchema       = "cathedral_cc_gpu_kbs_job_registration_ack_v1"
	SealedRegistrationAckSchema    = "cathedral_cc_gpu_kbs_sealed_input_registration_ack_v1"
	SealedStageRequestSchema       = "cathedral_cc_gpu_kbs_sealed_input_stage_request_v1"
	SealedStageAuthorizationSchema = "cathedral_cc_gpu_kbs_sealed_input_stage_authorization_v1"
	SealedStageAckSchema           = "cathedral_cc_gpu_kbs_sealed_input_staging_ack_v1"
	ReleaseJournalSchema           = "cathedral_cc_gpu_kbs_release_journal_v1"
	CompletionJournalSchema        = "cathedral_cc_gpu_kbs_completion_journal_v1"
	EKMLabel                       = "EXPORTER-Cathedral-CC-GPU-KBS-v1"
)

type Verifier interface {
	Verify(context.Context, string, map[string]any, map[string]any, string, any) error
}

type CommandVerifier struct {
	Path           string
	ExpectedSHA256 string
}

func (verifier CommandVerifier) Verify(ctx context.Context, phase string, expected, evidence map[string]any, tlsEKM string, finalize any) error {
	verifierRaw, readErr := os.ReadFile(verifier.Path)
	if verifier.Path == "" || !filepath.IsAbs(verifier.Path) || !contract.ValidDigest(verifier.ExpectedSHA256) || readErr != nil || contract.Digest(verifierRaw) != verifier.ExpectedSHA256 || phase != "admission" && phase != "completion" {
		return errors.New("pinned KBS verifier command is invalid")
	}
	input, _ := contract.CanonicalJSON(map[string]any{"expected": expected, "evidence": evidence, "tls_ekm_sha256": tlsEKM, "finalize_sha256": finalize})
	command := exec.CommandContext(ctx, verifier.Path, "verify-"+phase)
	command.Stdin = bytes.NewReader(input)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/nonexistent", "HOME=/nonexistent"}
	var output bytes.Buffer
	command.Stdout = &limitedBuffer{Buffer: &output, Maximum: contract.MaxDocumentBytes}
	command.Stderr = &limitedBuffer{Buffer: &bytes.Buffer{}, Maximum: 64 * 1024}
	if err := command.Run(); err != nil {
		return errors.New("pinned KBS verifier rejected evidence")
	}
	value, err := contract.StrictJSON(output.Bytes())
	verdict, ok := value.(map[string]any)
	if err != nil || !ok || verdict["verified"] != true || verdict["phase"] != phase || verdict["job_context_digest"] != expected["job_context_digest"] || verdict["attempt_id"] != expected["attempt_id"] || phase == "admission" && (verdict["runtime_isolation_verified"] != true || verdict["secret_release_authorized"] != true) {
		return errors.New("pinned KBS verifier returned an invalid verdict")
	}
	return nil
}

type limitedBuffer struct {
	*bytes.Buffer
	Maximum int
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	if buffer.Len()+len(value) > buffer.Maximum {
		return 0, errors.New("verifier output exceeds bound")
	}
	return buffer.Buffer.Write(value)
}

type JobStore struct {
	Directory string
}

type JobRecord struct {
	Expected           map[string]any
	AdmissionChallenge []byte
	GrantArtifact      []byte
	EncryptedItems     []any
	OutputKey          []byte
}

func (store JobStore) Load(jobID, attemptID string) (*JobRecord, error) {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || store.Directory == "" {
		return nil, errors.New("KBS job identity is invalid")
	}
	path := filepath.Join(store.Directory, jobID, attemptID+".json")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > contract.MaxDocumentBytes {
		return nil, errors.New("KBS job record is absent")
	}
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "schema", "expected", "admission_challenge_base64", "grant_artifact_base64", "encrypted_items", "output_key_base64") || document["schema"] != JobRecordSchema {
		return nil, errors.New("KBS job record has an invalid exact schema")
	}
	expected, expectedOK := document["expected"].(map[string]any)
	challenge, challengeErr := decodeBase64(document["admission_challenge_base64"], contract.MaxDocumentBytes)
	artifact, artifactErr := decodeBase64(document["grant_artifact_base64"], contract.MaxDocumentBytes)
	outputKey, keyErr := decodeBase64(document["output_key_base64"], 32)
	items, itemsOK := document["encrypted_items"].([]any)
	if !expectedOK || expected["job_id"] != jobID || expected["attempt_id"] != attemptID || challengeErr != nil || artifactErr != nil || keyErr != nil || len(outputKey) != 32 || !itemsOK || len(items) > 32 {
		return nil, errors.New("KBS job record bindings are invalid")
	}
	parsed, err := contract.ParseChallenge(challenge, "admission")
	if err != nil || !canonicalEqual(parsed.Expected, expected) {
		return nil, errors.New("KBS admission challenge differs from job expected contract")
	}
	declarations, declarationsOK := expected["request"].(map[string]any)["protected_inputs"].([]any)
	if !declarationsOK || len(items) != len(declarations) {
		return nil, errors.New("KBS encrypted item set differs from protected input declarations")
	}
	byReference := map[string]map[string]any{}
	var totalCiphertextBytes int64
	var totalPlaintextBytes int64
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || !contract.ExactKeys(item, "kind", "owner_digest", "sealed_reference", "sealed_record_sha256", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes", "nonce_prefix_base64", "key_base64") || !contract.ValidDigest(item["owner_digest"]) || !contract.ValidDigest(item["sealed_record_sha256"]) || !contract.ValidDigest(item["ciphertext_sha256"]) || !contract.ValidDigest(item["plaintext_sha256"]) {
			return nil, errors.New("KBS encrypted item has an invalid exact schema")
		}
		reference, referenceOK := item["sealed_reference"].(string)
		nonce, nonceErr := decodeBase64(item["nonce_prefix_base64"], 8)
		key, keyErr := decodeBase64(item["key_base64"], 32)
		cipherBytes, cipherOK := positiveInt64(item["ciphertext_bytes"])
		plainBytes, plainOK := positiveInt64(item["plaintext_bytes"])
		if !referenceOK || !contract.ValidSealedReference(reference, item["ciphertext_sha256"]) || byReference[reference] != nil || nonceErr != nil || keyErr != nil || len(nonce) != 8 || len(key) != 32 || !cipherOK || !plainOK || cipherBytes > contract.MaxProtectedCiphertextBytes || plainBytes > contract.MaxProtectedPlaintextBytes || totalCiphertextBytes > contract.MaxProtectedCiphertextBytes-cipherBytes || totalPlaintextBytes > contract.MaxProtectedPlaintextBytes-plainBytes {
			zero(key)
			return nil, errors.New("KBS encrypted item payload is invalid or duplicated")
		}
		totalCiphertextBytes += cipherBytes
		totalPlaintextBytes += plainBytes
		zero(key)
		byReference[reference] = item
	}
	for _, rawDeclaration := range declarations {
		declaration, ok := rawDeclaration.(map[string]any)
		reference, referenceOK := declaration["sealed_reference"].(string)
		item := byReference[reference]
		if !ok || !referenceOK || item == nil || item["kind"] != declaration["kind"] || item["owner_digest"] != expected["owner_digest"] || item["owner_digest"] != declaration["owner_digest"] || item["sealed_record_sha256"] != declaration["sealed_record_sha256"] || item["ciphertext_sha256"] != declaration["ciphertext_digest_sha256"] || item["plaintext_sha256"] != declaration["plaintext_digest_sha256"] || item["ciphertext_bytes"] != declaration["ciphertext_bytes"] || item["plaintext_bytes"] != declaration["plaintext_bytes"] {
			return nil, errors.New("KBS encrypted item differs from exact protected input declaration")
		}
	}
	return &JobRecord{Expected: expected, AdmissionChallenge: challenge, GrantArtifact: artifact, EncryptedItems: items, OutputKey: outputKey}, nil
}

func (store JobStore) CommitRelease(jobID, attemptID, requestDigest string, response []byte) ([]byte, error) {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || !contract.ValidDigest(requestDigest) || store.Directory == "" || len(response) == 0 || len(response) > contract.MaxDocumentBytes {
		return nil, errors.New("KBS release journal input is invalid")
	}
	responseValue, responseErr := contract.StrictJSON(response)
	responseDocument, responseOK := responseValue.(map[string]any)
	if responseErr != nil || !responseOK || responseDocument["schema"] != ReleaseResponseSchema {
		return nil, errors.New("KBS release response cannot be journaled")
	}
	directory := filepath.Join(store.Directory, jobID, "consumed")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("KBS consumption registry is unavailable")
	}
	path := filepath.Join(directory, attemptID+".release")
	readCommitted := func() ([]byte, error) {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() < 1 || info.Size() > 2*contract.MaxDocumentBytes {
			return nil, errors.New("KBS release journal is absent or oversized")
		}
		raw, readErr := os.ReadFile(path)
		value, parseErr := contract.StrictJSON(raw)
		document, ok := value.(map[string]any)
		if readErr != nil || parseErr != nil || !ok || !contract.ExactKeys(document, "schema", "request_digest", "response_sha256", "response_base64") || document["schema"] != ReleaseJournalSchema || document["request_digest"] != requestDigest || !contract.ValidDigest(document["response_sha256"]) {
			return nil, errors.New("KBS one-time release request was already consumed by a different request")
		}
		encoded, encodedOK := document["response_base64"].(string)
		committed, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if !encodedOK || decodeErr != nil || base64.StdEncoding.EncodeToString(committed) != encoded || len(committed) == 0 || len(committed) > contract.MaxDocumentBytes || contract.Digest(committed) != document["response_sha256"] {
			return nil, errors.New("KBS release journal response is invalid")
		}
		return committed, nil
	}
	if _, err := os.Stat(path); err == nil {
		return readCommitted()
	} else if !os.IsNotExist(err) {
		return nil, errors.New("KBS release journal is unavailable")
	}
	journal, err := contract.CanonicalJSON(map[string]any{
		"schema": ReleaseJournalSchema, "request_digest": requestDigest,
		"response_sha256": contract.Digest(response), "response_base64": base64.StdEncoding.EncodeToString(response),
	})
	if err != nil {
		return nil, errors.New("KBS release journal could not be encoded")
	}
	temporary, err := os.CreateTemp(directory, ".release-journal-*")
	if err != nil {
		return nil, errors.New("KBS release journal temporary file is unavailable")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS release journal permissions could not be enforced")
	}
	if _, err := temporary.Write(journal); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS release journal could not be persisted")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS release journal could not be synced")
	}
	if err := temporary.Close(); err != nil {
		return nil, errors.New("KBS release journal could not be persisted")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if os.IsExist(err) {
			return readCommitted()
		}
		return nil, errors.New("KBS release journal could not be committed")
	}
	if err := syncDirectory(directory); err != nil {
		return nil, errors.New("KBS release journal directory could not be synced")
	}
	return append([]byte(nil), response...), nil
}

func (store JobStore) ConsumeStagingAuthorization(authorizationID, authorizationDigest string) error {
	if !contract.ValidUUID(authorizationID) || !contract.ValidDigest(authorizationDigest) || store.Directory == "" {
		return errors.New("KBS staging authorization identity is invalid")
	}
	directory := filepath.Join(store.Directory, "staging-authorizations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("KBS staging authorization registry is unavailable")
	}
	file, err := os.OpenFile(filepath.Join(directory, authorizationID+".stage"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		existing, readErr := os.ReadFile(filepath.Join(directory, authorizationID+".stage"))
		if readErr == nil && string(existing) == authorizationDigest {
			return nil
		}
		return errors.New("KBS staging authorization ID was reused with a different signed artifact")
	}
	if _, err := file.Write([]byte(authorizationDigest)); err != nil {
		_ = file.Close()
		return errors.New("KBS staging authorization marker could not be persisted")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("KBS staging authorization marker could not be synced")
	}
	if err := file.Close(); err != nil {
		return errors.New("KBS staging authorization marker could not be persisted")
	}
	return syncDirectory(directory)
}

func (store JobStore) StoreSealed(raw []byte) (string, map[string]any, error) {
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	canonical, _ := contract.CanonicalJSON(document)
	if err != nil || !ok || !bytes.Equal(raw, canonical) || !validSealedRecord(document) {
		return "", nil, errors.New("KBS sealed input record is not canonical or valid")
	}
	digest := contract.Digest(raw)
	directory := filepath.Join(store.Directory, "sealed-records")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", nil, errors.New("KBS sealed input registry is unavailable")
	}
	path := filepath.Join(directory, strings.TrimPrefix(digest, "sha256:")+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(existing, raw) {
			if bindErr := store.bindSealedIndex(document["ciphertext_sha256"].(string), digest); bindErr != nil {
				return "", nil, bindErr
			}
			return digest, document, nil
		}
		return "", nil, errors.New("KBS sealed input record conflicts with immutable registry")
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return "", nil, errors.New("KBS sealed input record persistence failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", nil, errors.New("KBS sealed input record sync failed")
	}
	if err := file.Close(); err != nil {
		return "", nil, errors.New("KBS sealed input record persistence failed")
	}
	if err := syncDirectory(directory); err != nil {
		return "", nil, errors.New("KBS sealed input registry sync failed")
	}
	if err := store.bindSealedIndex(document["ciphertext_sha256"].(string), digest); err != nil {
		return "", nil, err
	}
	return digest, document, nil
}

func (store JobStore) bindSealedIndex(ciphertextDigest, recordDigest string) error {
	if !contract.ValidDigest(ciphertextDigest) || !contract.ValidDigest(recordDigest) {
		return errors.New("KBS sealed input index binding is invalid")
	}
	directory := filepath.Join(store.Directory, "sealed-index")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("KBS sealed input index is unavailable")
	}
	path := filepath.Join(directory, strings.TrimPrefix(ciphertextDigest, "sha256:")+".record")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && string(existing) == recordDigest {
			return nil
		}
		return errors.New("KBS ciphertext is already bound to a different sealed-key record")
	}
	if _, err := file.Write([]byte(recordDigest)); err != nil {
		_ = file.Close()
		return errors.New("KBS sealed input index persistence failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("KBS sealed input index sync failed")
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func (store JobStore) LoadSealed(digest string) (map[string]any, error) {
	if !contract.ValidDigest(digest) {
		return nil, errors.New("KBS sealed record digest is invalid")
	}
	raw, err := os.ReadFile(filepath.Join(store.Directory, "sealed-records", strings.TrimPrefix(digest, "sha256:")+".json"))
	value, parseErr := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	canonical, _ := contract.CanonicalJSON(document)
	if err != nil || parseErr != nil || !ok || contract.Digest(raw) != digest || !bytes.Equal(raw, canonical) || !validSealedRecord(document) {
		return nil, errors.New("KBS sealed input record is absent or invalid")
	}
	index, indexErr := os.ReadFile(filepath.Join(store.Directory, "sealed-index", strings.TrimPrefix(document["ciphertext_sha256"].(string), "sha256:")+".record"))
	if indexErr != nil || string(index) != digest {
		return nil, errors.New("KBS sealed input record is not the unique ciphertext-key binding")
	}
	return document, nil
}

func validSealedRecord(document map[string]any) bool {
	if !contract.ExactKeys(document, "schema", "owner_digest", "kind", "sealed_reference", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes", "nonce_prefix_base64", "key_base64") || document["schema"] != SealedRecordSchema || !contract.ValidDigest(document["owner_digest"]) {
		return false
	}
	kind, kindOK := document["kind"].(string)
	reference, referenceOK := document["sealed_reference"].(string)
	cipherBytes, cipherOK := positiveInt64(document["ciphertext_bytes"])
	plainBytes, plainOK := positiveInt64(document["plaintext_bytes"])
	nonce, nonceErr := decodeBase64(document["nonce_prefix_base64"], 8)
	key, keyErr := decodeBase64(document["key_base64"], 32)
	defer zero(key)
	return kindOK && (kind == "input" || kind == "model" || kind == "secret") && referenceOK && contract.ValidSealedReference(reference, document["ciphertext_sha256"]) && contract.ValidDigest(document["plaintext_sha256"]) && cipherOK && plainOK && cipherBytes <= contract.MaxProtectedCiphertextBytes && plainBytes <= contract.MaxProtectedPlaintextBytes && nonceErr == nil && len(nonce) == 8 && keyErr == nil && len(key) == 32
}

type Registration struct {
	JobID                   string
	AttemptID               string
	JobContextDigest        string
	OwnerDigest             string
	ProtectedInputSetDigest string
	SealedRecordSHA256s     []any
	JobRecordSHA256         string
	AdminCertificateSHA256  string
}

func (store JobStore) Register(raw []byte, adminCertificateSHA256 string, now time.Time, grantArtifact []byte) (*Registration, error) {
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "schema", "expected", "admission_challenge_base64") || document["schema"] != JobRegistrationSchema || !contract.ValidDigest(adminCertificateSHA256) {
		return nil, errors.New("KBS job registration request has an invalid exact schema")
	}
	expected, expectedOK := document["expected"].(map[string]any)
	if !expectedOK {
		return nil, errors.New("KBS job registration expected contract is invalid")
	}
	jobID, jobOK := expected["job_id"].(string)
	attemptID, attemptOK := expected["attempt_id"].(string)
	canonical, _ := contract.CanonicalJSON(document)
	if err != nil || !ok || !expectedOK || !jobOK || !attemptOK || !bytes.Equal(raw, canonical) || filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID {
		return nil, errors.New("KBS registered job request is not canonical or lacks exact IDs")
	}
	challenge, challengeErr := decodeBase64(document["admission_challenge_base64"], contract.MaxDocumentBytes)
	parsed, parseErr := contract.ParseChallenge(challenge, "admission")
	if challengeErr != nil || parseErr != nil || !canonicalEqual(parsed.Expected, expected) {
		return nil, errors.New("KBS job registration challenge differs from expected contract")
	}
	if _, err := contract.ValidateReleasePolicy(grantArtifact, expected, now); err != nil {
		return nil, err
	}
	declarations, declarationsOK := expected["request"].(map[string]any)["protected_inputs"].([]any)
	if !declarationsOK || len(declarations) > 32 {
		return nil, errors.New("KBS job registration sealed record set is invalid")
	}
	digests := make([]any, 0, len(declarations))
	items := make([]any, 0, len(declarations))
	seen := map[string]bool{}
	for _, rawDeclaration := range declarations {
		declaration, declarationOK := rawDeclaration.(map[string]any)
		digest, digestOK := declaration["sealed_record_sha256"].(string)
		if !digestOK || seen[digest] {
			return nil, errors.New("KBS job registration sealed record digest is invalid or duplicated")
		}
		seen[digest] = true
		digests = append(digests, digest)
		record, loadErr := store.LoadSealed(digest)
		if loadErr != nil || !declarationOK || record["owner_digest"] != expected["owner_digest"] || record["owner_digest"] != declaration["owner_digest"] || record["kind"] != declaration["kind"] || record["sealed_reference"] != declaration["sealed_reference"] || record["ciphertext_sha256"] != declaration["ciphertext_digest_sha256"] || record["plaintext_sha256"] != declaration["plaintext_digest_sha256"] || !canonicalEqual(record["ciphertext_bytes"], declaration["ciphertext_bytes"]) || !canonicalEqual(record["plaintext_bytes"], declaration["plaintext_bytes"]) {
			return nil, errors.New("KBS sealed record differs from ordered protected input declaration")
		}
		item := make(map[string]any, len(record)-1)
		for key, itemValue := range record {
			if key != "schema" {
				item[key] = itemValue
			}
		}
		item["sealed_record_sha256"] = digest
		items = append(items, item)
	}
	outputKey := make([]byte, 32)
	if _, err := rand.Read(outputKey); err != nil {
		return nil, errors.New("KBS output sealing key generation failed")
	}
	defer zero(outputKey)
	internalDocument := map[string]any{
		"schema": JobRecordSchema, "expected": expected,
		"admission_challenge_base64": document["admission_challenge_base64"], "grant_artifact_base64": base64.StdEncoding.EncodeToString(grantArtifact),
		"encrypted_items": items, "output_key_base64": base64.StdEncoding.EncodeToString(outputKey),
	}
	internalRaw, _ := contract.CanonicalJSON(internalDocument)
	temporary, err := os.MkdirTemp(store.Directory, ".register-validate-")
	if err != nil {
		return nil, errors.New("KBS job validation directory is unavailable")
	}
	defer os.RemoveAll(temporary)
	validationDirectory := filepath.Join(temporary, jobID)
	if os.Mkdir(validationDirectory, 0o700) != nil || os.WriteFile(filepath.Join(validationDirectory, attemptID+".json"), internalRaw, 0o600) != nil {
		return nil, errors.New("KBS job record could not be staged for validation")
	}
	if _, err := (JobStore{Directory: temporary}).Load(jobID, attemptID); err != nil {
		return nil, err
	}
	directory := filepath.Join(store.Directory, jobID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("KBS registered job directory is unavailable")
	}
	file, err := os.OpenFile(filepath.Join(directory, attemptID+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("KBS job record already exists")
	}
	if _, err := file.Write(internalRaw); err != nil {
		_ = file.Close()
		return nil, errors.New("KBS job record persistence failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, errors.New("KBS job record sync failed")
	}
	if err := file.Close(); err != nil {
		return nil, errors.New("KBS job record persistence failed")
	}
	if err := syncDirectory(directory); err != nil {
		return nil, errors.New("KBS registered job directory sync failed")
	}
	return &Registration{JobID: jobID, AttemptID: attemptID, JobContextDigest: expected["job_context_digest"].(string), OwnerDigest: expected["owner_digest"].(string), ProtectedInputSetDigest: expected["request"].(map[string]any)["protected_input_set_digest"].(string), SealedRecordSHA256s: digests, JobRecordSHA256: contract.Digest(internalRaw), AdminCertificateSHA256: adminCertificateSHA256}, nil
}

func (store JobStore) BeginCompletion(jobID, attemptID, digest string, challenge []byte) error {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || !contract.ValidDigest(digest) || contract.Digest(challenge) != digest {
		return errors.New("KBS completion challenge digest is invalid")
	}
	directory := filepath.Join(store.Directory, jobID, "completion-pending")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("KBS completion registry is unavailable")
	}
	if _, err := os.Stat(filepath.Join(store.Directory, jobID, "completion-consumed", attemptID+".json")); err == nil {
		return errors.New("KBS completion challenge was already consumed")
	}
	file, err := os.OpenFile(filepath.Join(directory, attemptID+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		existing, readErr := os.ReadFile(filepath.Join(directory, attemptID+".json"))
		if readErr == nil && bytes.Equal(existing, challenge) {
			return nil
		}
		return errors.New("KBS completion challenge is duplicated or replayed")
	}
	if _, err := file.Write(challenge); err != nil {
		_ = file.Close()
		return errors.New("KBS completion challenge could not be persisted")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("KBS completion challenge could not be synced")
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func (store JobStore) ReadCompletion(jobID, attemptID, digest string, now time.Time) ([]byte, error) {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || !contract.ValidDigest(digest) {
		return nil, errors.New("KBS completion identity is invalid")
	}
	pending := filepath.Join(store.Directory, jobID, "completion-pending", attemptID+".json")
	info, err := os.Stat(pending)
	if err != nil || now.Before(info.ModTime().Add(-30*time.Second)) || now.After(info.ModTime().Add(10*time.Minute)) {
		return nil, errors.New("KBS completion challenge is absent, stale, or replayed")
	}
	raw, err := os.ReadFile(pending)
	if err != nil || contract.Digest(raw) != digest {
		return nil, errors.New("KBS pending completion challenge is invalid")
	}
	return raw, nil
}

func (store JobStore) CompletionResponse(jobID, attemptID, challengeDigest, requestDigest string) ([]byte, bool, error) {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || !contract.ValidDigest(challengeDigest) || !contract.ValidDigest(requestDigest) {
		return nil, false, errors.New("KBS completion identity is invalid")
	}
	path := filepath.Join(store.Directory, jobID, "completion-consumed", attemptID+".json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	value, parseErr := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || parseErr != nil || !ok || !contract.ExactKeys(document, "schema", "challenge_digest", "request_digest", "response_sha256", "response_base64") || document["schema"] != CompletionJournalSchema || document["challenge_digest"] != challengeDigest || document["request_digest"] != requestDigest || !contract.ValidDigest(document["response_sha256"]) {
		return nil, true, errors.New("KBS completion attempt was already consumed by a different request")
	}
	encoded, encodedOK := document["response_base64"].(string)
	response, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
	if !encodedOK || decodeErr != nil || base64.StdEncoding.EncodeToString(response) != encoded || len(response) == 0 || len(response) > contract.MaxDocumentBytes || contract.Digest(response) != document["response_sha256"] {
		return nil, true, errors.New("KBS completion journal response is invalid")
	}
	return response, true, nil
}

func (store JobStore) CommitCompletion(jobID, attemptID, challengeDigest, requestDigest string, response []byte) ([]byte, error) {
	if filepath.Base(jobID) != jobID || filepath.Base(attemptID) != attemptID || !contract.ValidDigest(challengeDigest) || !contract.ValidDigest(requestDigest) || len(response) == 0 || len(response) > contract.MaxDocumentBytes {
		return nil, errors.New("KBS completion identity is invalid")
	}
	if committed, exists, err := store.CompletionResponse(jobID, attemptID, challengeDigest, requestDigest); exists || err != nil {
		return committed, err
	}
	value, parseErr := contract.StrictJSON(response)
	document, ok := value.(map[string]any)
	if parseErr != nil || !ok || document["schema"] != CompletionAckSchema {
		return nil, errors.New("KBS completion response cannot be journaled")
	}
	pending := filepath.Join(store.Directory, jobID, "completion-pending", attemptID+".json")
	if raw, err := os.ReadFile(pending); err != nil || contract.Digest(raw) != challengeDigest {
		return nil, errors.New("KBS completion challenge is absent or mismatched")
	}
	consumedDirectory := filepath.Join(store.Directory, jobID, "completion-consumed")
	if err := os.MkdirAll(consumedDirectory, 0o700); err != nil {
		return nil, errors.New("KBS completion consumed registry is unavailable")
	}
	journal, err := contract.CanonicalJSON(map[string]any{
		"schema": CompletionJournalSchema, "challenge_digest": challengeDigest, "request_digest": requestDigest,
		"response_sha256": contract.Digest(response), "response_base64": base64.StdEncoding.EncodeToString(response),
	})
	if err != nil {
		return nil, errors.New("KBS completion journal could not be encoded")
	}
	temporary, err := os.CreateTemp(consumedDirectory, ".completion-journal-*")
	if err != nil {
		return nil, errors.New("KBS completion journal temporary file is unavailable")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS completion journal permissions could not be enforced")
	}
	if _, err := temporary.Write(journal); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS completion journal could not be persisted")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, errors.New("KBS completion journal could not be synced")
	}
	if err := temporary.Close(); err != nil {
		return nil, errors.New("KBS completion journal could not be persisted")
	}
	path := filepath.Join(consumedDirectory, attemptID+".json")
	if err := os.Link(temporaryPath, path); err != nil {
		if os.IsExist(err) {
			committed, _, readErr := store.CompletionResponse(jobID, attemptID, challengeDigest, requestDigest)
			return committed, readErr
		}
		return nil, errors.New("KBS completion journal could not be committed")
	}
	if err := syncDirectory(consumedDirectory); err != nil {
		return nil, errors.New("KBS completion consumed registry could not be synced")
	}
	// The durable journal is the authoritative consumed marker. A crash or
	// cleanup failure may leave the pending challenge, but can never enable a
	// second response; BeginCompletion checks the journal first.
	if err := os.Remove(pending); err == nil {
		_ = syncDirectory(filepath.Dir(pending))
	}
	return append([]byte(nil), response...), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type Server struct {
	Verifier             Verifier
	Jobs                 JobStore
	SigningKey           ed25519.PrivateKey
	SigningKeyID         string
	ConfigSHA256         string
	StagingAuthorityKeys map[string]ed25519.PublicKey
	Now                  func() time.Time
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || request.URL.RawQuery != "" {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, contract.MaxDocumentBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	var result []byte
	switch request.URL.Path {
	case "/v1/staging/sealed-inputs":
		result, err = server.stageSealed(raw)
	case "/v1/admin/jobs", "/v1/admin/sealed-inputs":
		if len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		adminCertificateSHA256 := contract.Digest(request.TLS.PeerCertificates[0].Raw)
		if request.URL.Path == "/v1/admin/jobs" {
			result, err = server.register(raw, adminCertificateSHA256)
		} else {
			result, err = server.registerSealed(raw, adminCertificateSHA256)
		}
	case "/v1/releases/challenge":
		result, err = server.challenge(raw)
	case "/v1/releases":
		result, err = server.release(request.Context(), request.TLS, raw)
	case "/v1/attestations/completion/challenge":
		result, err = server.completionStart(raw)
	case "/v1/attestations/completion":
		result, err = server.completion(request.Context(), request.TLS, raw)
	default:
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(response, "request rejected", http.StatusPreconditionFailed)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = response.Write(result)
}

func (server *Server) stageSealed(raw []byte) ([]byte, error) {
	document, err := strictObject(raw, "schema", "sealed_record", "authorization")
	record, recordOK := document["sealed_record"].(map[string]any)
	authorization, authorizationOK := document["authorization"].(map[string]any)
	canonical, _ := contract.CanonicalJSON(document)
	if err != nil || !recordOK || !authorizationOK || document["schema"] != SealedStageRequestSchema || !bytes.Equal(raw, canonical) {
		return nil, errors.New("KBS sealed-input staging request is invalid or non-canonical")
	}
	recordRaw, _ := contract.CanonicalJSON(record)
	authorizationRaw, _ := contract.CanonicalJSON(authorization)
	if err := server.validateStagingAuthorization(authorization, record, recordRaw); err != nil {
		return nil, err
	}
	authorizationID := authorization["authorization_id"].(string)
	authorizationDigest := contract.Digest(authorizationRaw)
	if err := server.Jobs.ConsumeStagingAuthorization(authorizationID, authorizationDigest); err != nil {
		return nil, err
	}
	digest, stored, err := server.Jobs.StoreSealed(recordRaw)
	if err != nil {
		return nil, err
	}
	ack := map[string]any{
		"schema": SealedStageAckSchema, "sealed_record_sha256": digest, "owner_digest": stored["owner_digest"],
		"sealed_reference": stored["sealed_reference"], "ciphertext_sha256": stored["ciphertext_sha256"],
		"staging_authorization_sha256": authorizationDigest,
		"registered_at":                server.now().Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": server.SigningKeyID,
	}
	return server.sign(ack)
}

func (server *Server) validateStagingAuthorization(authorization, record map[string]any, recordRaw []byte) error {
	if !validSealedRecord(record) || !contract.ExactKeys(authorization,
		"schema", "authorization_id", "owner_digest", "sealed_record_sha256", "kind", "sealed_reference", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes", "issued_at", "expires_at", "signing_key_id", "signature",
	) || authorization["schema"] != SealedStageAuthorizationSchema || !contract.ValidUUID(authorization["authorization_id"]) || authorization["sealed_record_sha256"] != contract.Digest(recordRaw) {
		return errors.New("KBS sealed-input staging authorization has an invalid exact binding")
	}
	for _, key := range []string{"owner_digest", "kind", "sealed_reference", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes"} {
		if !canonicalEqual(authorization[key], record[key]) {
			return errors.New("KBS sealed-input staging authorization differs from sealed record")
		}
	}
	issuedText, issuedOK := authorization["issued_at"].(string)
	expiresText, expiresOK := authorization["expires_at"].(string)
	issued, issuedErr := time.Parse("2006-01-02T15:04:05.000000Z", issuedText)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05.000000Z", expiresText)
	now := server.now()
	if !issuedOK || !expiresOK || issuedErr != nil || expiresErr != nil || issued.Format("2006-01-02T15:04:05.000000Z") != issuedText || expires.Format("2006-01-02T15:04:05.000000Z") != expiresText || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute || now.Before(issued.Add(-30*time.Second)) || now.After(expires.Add(30*time.Second)) {
		return errors.New("KBS sealed-input staging authorization is stale, future, overlong, or non-canonical")
	}
	keyID, keyOK := authorization["signing_key_id"].(string)
	publicKey, keyPresent := server.StagingAuthorityKeys[keyID]
	if !keyOK || keyID == "" || !keyPresent || verifyEd25519(authorization, keyID, publicKey) != nil {
		return errors.New("KBS sealed-input staging authorization signature is invalid")
	}
	return nil
}

func (server *Server) register(raw []byte, adminCertificateSHA256 string) ([]byte, error) {
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	expected, expectedOK := document["expected"].(map[string]any)
	if err != nil || !ok || !expectedOK {
		return nil, errors.New("KBS job registration request is invalid")
	}
	now := server.now()
	grantArtifact, err := server.releasePolicy(expected, now)
	if err != nil {
		return nil, err
	}
	registration, err := server.Jobs.Register(raw, adminCertificateSHA256, now, grantArtifact)
	if err != nil {
		return nil, err
	}
	ack := map[string]any{
		"schema": JobRegistrationAckSchema, "job_id": registration.JobID, "attempt_id": registration.AttemptID,
		"job_context_digest": registration.JobContextDigest, "owner_digest": registration.OwnerDigest, "protected_input_set_digest": registration.ProtectedInputSetDigest,
		"sealed_record_sha256s": registration.SealedRecordSHA256s, "job_record_sha256": registration.JobRecordSHA256,
		"admin_client_certificate_sha256": registration.AdminCertificateSHA256,
		"registered_at":                   server.now().Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": server.SigningKeyID,
	}
	return server.sign(ack)
}

func (server *Server) releasePolicy(expected map[string]any, now time.Time) ([]byte, error) {
	request, requestOK := expected["request"].(map[string]any)
	inputs, inputsOK := request["protected_inputs"].([]any)
	if !requestOK || !inputsOK {
		return nil, errors.New("KBS release policy source contract is invalid")
	}
	digests := make([]any, len(inputs))
	for index, rawInput := range inputs {
		input, ok := rawInput.(map[string]any)
		if !ok || !contract.ValidDigest(input["sealed_record_sha256"]) {
			return nil, errors.New("KBS release policy sealed record is invalid")
		}
		digests[index] = input["sealed_record_sha256"]
	}
	recipientRaw, _ := contract.CanonicalJSON(request["output_recipient"])
	document := map[string]any{
		"schema": contract.KBSReleasePolicySchema, "execution_class": "cc_gpu", "profile_id": contract.ProfileID,
		"job_id": expected["job_id"], "attempt_id": expected["attempt_id"], "job_context_digest": expected["job_context_digest"], "owner_digest": expected["owner_digest"],
		"protected_input_set_digest": request["protected_input_set_digest"], "sealed_record_sha256s": digests,
		"output_recipient_digest": contract.Digest(recipientRaw), "issued_at": now.Format("2006-01-02T15:04:05.000000Z"),
		"expires_at": now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": server.SigningKeyID,
	}
	return server.sign(document)
}

func (server *Server) registerSealed(raw []byte, adminCertificateSHA256 string) ([]byte, error) {
	digest, record, err := server.Jobs.StoreSealed(raw)
	if err != nil {
		return nil, err
	}
	ack := map[string]any{
		"schema": SealedRegistrationAckSchema, "sealed_record_sha256": digest,
		"owner_digest": record["owner_digest"], "sealed_reference": record["sealed_reference"], "ciphertext_sha256": record["ciphertext_sha256"],
		"admin_client_certificate_sha256": adminCertificateSHA256,
		"registered_at":                   server.now().Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": server.SigningKeyID,
	}
	return server.sign(ack)
}

func (server *Server) sign(document map[string]any) ([]byte, error) {
	unsigned, err := contract.CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	document["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(server.SigningKey, unsigned))}
	return contract.CanonicalJSON(document)
}

func (server *Server) challenge(raw []byte) ([]byte, error) {
	document, err := strictObject(raw, "schema", "request")
	request, ok := document["request"].(map[string]any)
	if err != nil || document["schema"] != ChallengeRequestSchema || !ok || !validReleaseRequest(request) {
		return nil, errors.New("KBS challenge request is invalid")
	}
	record, err := server.Jobs.Load(request["job_id"].(string), request["attempt_id"].(string))
	if err != nil || request["job_context_digest"] != record.Expected["job_context_digest"] || request["protected_input_set_digest"] != record.Expected["request"].(map[string]any)["protected_input_set_digest"] {
		return nil, errors.New("KBS challenge request differs from registered job")
	}
	return contract.CanonicalJSON(map[string]any{"schema": ChallengeSchema, "challenge_base64": base64.StdEncoding.EncodeToString(record.AdmissionChallenge), "challenge_sha256": contract.Digest(record.AdmissionChallenge)})
}

func (server *Server) release(ctx context.Context, tlsState *tls.ConnectionState, raw []byte) ([]byte, error) {
	document, err := strictObject(raw, "schema", "request", "evidence")
	request, requestOK := document["request"].(map[string]any)
	evidence, evidenceOK := document["evidence"].(map[string]any)
	if err != nil || document["schema"] != ReleaseSubmitSchema || !requestOK || !evidenceOK || !validReleaseRequest(request) {
		return nil, errors.New("KBS release submission is invalid")
	}
	record, err := server.Jobs.Load(request["job_id"].(string), request["attempt_id"].(string))
	if err != nil || request["job_context_digest"] != record.Expected["job_context_digest"] || request["protected_input_set_digest"] != record.Expected["request"].(map[string]any)["protected_input_set_digest"] {
		return nil, errors.New("KBS release differs from registered job")
	}
	defer zero(record.OutputKey)
	policyDocument, err := contract.ValidateReleasePolicy(record.GrantArtifact, record.Expected, server.now())
	if err != nil || verifyEd25519(policyDocument, server.SigningKeyID, server.SigningKey.Public().(ed25519.PublicKey)) != nil {
		return nil, errors.New("KBS release policy is invalid, stale, or not signed by this KBS")
	}
	state := *tlsState
	ekm, err := state.ExportKeyingMaterial(EKMLabel, nil, 32)
	if err != nil {
		return nil, errors.New("KBS release EKM derivation failed")
	}
	tlsDigest := contract.Digest(ekm)
	zero(ekm)
	if err := server.Verifier.Verify(ctx, "admission", record.Expected, evidence, tlsDigest, nil); err != nil {
		return nil, err
	}
	token, ready, evidenceErr := releaseEvidenceBindings(evidence)
	if evidenceErr != nil {
		return nil, evidenceErr
	}
	requestRaw, _ := contract.CanonicalJSON(request)
	requestDigest := contract.Digest(requestRaw)
	now := server.now()
	ack := map[string]any{
		"schema": ReleaseAckSchema, "grant_id": randomID(), "job_id": request["job_id"], "attempt_id": request["attempt_id"],
		"job_context_digest": request["job_context_digest"], "channel_key_sha256": ready["channel_key_sha256"], "channel_binding_sha256": ready["channel_binding_sha256"],
		"protected_input_set_digest": request["protected_input_set_digest"], "admission_evidence_sha256": digestCanonical(evidence),
		"admission_token_sha256": contract.Digest([]byte(token)), "tls_ekm_sha256": tlsDigest,
		"one_time_nonce_digest": request["one_time_nonce_digest"], "grant_artifact_sha256": contract.Digest(record.GrantArtifact), "release_request_sha256": requestDigest,
		"issued_at": now.Format("2006-01-02T15:04:05.000000Z"), "expires_at": now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000000Z"),
		"single_use": true, "consumed_at": now.Format("2006-01-02T15:04:05.000000Z"), "signing_key_id": server.SigningKeyID, "kbs_config_sha256": server.ConfigSHA256,
	}
	unsigned, _ := contract.CanonicalJSON(ack)
	ack["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(server.SigningKey, unsigned))}
	response, err := contract.CanonicalJSON(map[string]any{
		"schema": ReleaseResponseSchema, "ack": ack, "grant_artifact_base64": base64.StdEncoding.EncodeToString(record.GrantArtifact),
		"encrypted_items": record.EncryptedItems, "output_key_base64": base64.StdEncoding.EncodeToString(record.OutputKey),
	})
	if err != nil {
		return nil, err
	}
	return server.Jobs.CommitRelease(
		request["job_id"].(string), request["attempt_id"].(string), requestDigest, response,
	)
}

func (server *Server) completionStart(raw []byte) ([]byte, error) {
	document, err := strictObject(raw, "schema", "challenge_base64", "challenge_sha256")
	challenge, decodeErr := decodeBase64(document["challenge_base64"], contract.MaxDocumentBytes)
	if err != nil || document["schema"] != CompletionStartSchema || decodeErr != nil || document["challenge_sha256"] != contract.Digest(challenge) {
		return nil, errors.New("KBS completion start is invalid")
	}
	parsed, err := contract.ParseChallenge(challenge, "completion")
	if err != nil {
		return nil, err
	}
	record, err := server.Jobs.Load(parsed.Expected["job_id"].(string), parsed.Expected["attempt_id"].(string))
	if err != nil || !canonicalEqual(record.Expected, admissionExpected(parsed.Expected)) {
		return nil, errors.New("KBS completion challenge differs from registered job")
	}
	if err := server.Jobs.BeginCompletion(parsed.Expected["job_id"].(string), parsed.Expected["attempt_id"].(string), contract.Digest(challenge), challenge); err != nil {
		return nil, err
	}
	return contract.CanonicalJSON(map[string]any{"schema": CompletionStartSchema, "challenge_sha256": contract.Digest(challenge), "accepted": true})
}

func (server *Server) completion(ctx context.Context, tlsState *tls.ConnectionState, raw []byte) ([]byte, error) {
	document, err := strictObject(raw, "schema", "job_id", "attempt_id", "challenge_sha256", "evidence")
	evidence, ok := document["evidence"].(map[string]any)
	digest, digestOK := document["challenge_sha256"].(string)
	jobID, jobOK := document["job_id"].(string)
	attemptID, attemptOK := document["attempt_id"].(string)
	if err != nil || document["schema"] != CompletionAckSchema || !ok || !digestOK || !jobOK || !attemptOK {
		return nil, errors.New("KBS completion submission is invalid")
	}
	requestDigest := contract.Digest(raw)
	if committed, exists, replayErr := server.Jobs.CompletionResponse(jobID, attemptID, digest, requestDigest); exists || replayErr != nil {
		return committed, replayErr
	}
	challengeRaw, err := server.Jobs.ReadCompletion(jobID, attemptID, digest, server.now())
	if err != nil {
		return nil, err
	}
	challenge, _ := contract.ParseChallenge(challengeRaw, "completion")
	if challenge.Expected["job_id"] != jobID || challenge.Expected["attempt_id"] != attemptID {
		return nil, errors.New("KBS completion submission changed the registered attempt")
	}
	state := *tlsState
	ekm, err := state.ExportKeyingMaterial(EKMLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	tlsDigest := contract.Digest(ekm)
	zero(ekm)
	if err := server.Verifier.Verify(ctx, "completion", challenge.Expected, evidence, tlsDigest, challenge.FinalizeSHA256); err != nil {
		return nil, err
	}
	evidenceRaw, _ := contract.CanonicalJSON(evidence)
	response, err := contract.CanonicalJSON(map[string]any{"schema": CompletionAckSchema, "challenge_sha256": digest, "evidence_sha256": contract.Digest(evidenceRaw), "verified": true})
	if err != nil {
		return nil, err
	}
	return server.Jobs.CommitCompletion(jobID, attemptID, digest, requestDigest, response)
}

func (server *Server) now() time.Time {
	if server.Now != nil {
		return server.Now().UTC()
	}
	return time.Now().UTC()
}

func validReleaseRequest(document map[string]any) bool {
	return contract.ExactKeys(document, "schema", "job_id", "attempt_id", "job_context_digest", "protected_input_set_digest", "one_time_nonce_digest") && document["schema"] == ReleaseRequestSchema && contract.ValidDigest(document["job_context_digest"]) && contract.ValidDigest(document["protected_input_set_digest"]) && contract.ValidDigest(document["one_time_nonce_digest"])
}

func releaseEvidenceBindings(evidence map[string]any) (string, map[string]any, error) {
	token, tokenOK := evidence["attestation_token"].(string)
	proof, proofOK := evidence["channel_proof"].(map[string]any)
	if !tokenOK || token == "" || !proofOK {
		return "", nil, errors.New("KBS admission evidence lacks exact token/channel bindings")
	}
	ready, readyOK := proof["ready_assertion"].(map[string]any)
	if !readyOK || !contract.ValidHex(ready["channel_key_sha256"]) || !contract.ValidHex(ready["channel_binding_sha256"]) {
		return "", nil, errors.New("KBS admission evidence lacks a valid Ready channel")
	}
	return token, ready, nil
}

func verifyEd25519(document map[string]any, keyID string, publicKey ed25519.PublicKey) error {
	if document["signing_key_id"] != keyID || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("signed artifact key is mismatched")
	}
	signatureObject, ok := document["signature"].(map[string]any)
	if !ok || !contract.ExactKeys(signatureObject, "algorithm", "value_base64") || signatureObject["algorithm"] != "ed25519" {
		return errors.New("signed artifact signature schema is invalid")
	}
	signature, err := decodeBase64(signatureObject["value_base64"], ed25519.SignatureSize)
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
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("signed artifact signature verification failed")
	}
	return nil
}

func strictObject(raw []byte, keys ...string) (map[string]any, error) {
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, keys...) {
		return nil, errors.New("KBS JSON has an invalid exact schema")
	}
	return document, nil
}

func decodeBase64(value any, maximum int) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("KBS base64 value is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, errors.New("KBS base64 value is not canonical or bounded")
	}
	return decoded, nil
}

func positiveInt64(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil && parsed > 0
}

func digestCanonical(value any) string {
	raw, _ := contract.CanonicalJSON(value)
	return contract.Digest(raw)
}
func admissionExpected(completion map[string]any) map[string]any {
	result := make(map[string]any, len(completion)-5)
	for key, value := range completion {
		switch key {
		case "result_sha256", "artifact_manifest_sha256", "admission_bundle_sha256", "admission_gpu_identity_set_sha256", "kbs_release_ack_sha256":
		default:
			result[key] = value
		}
	}
	result["phase"] = "admission"
	result["nonce_digest"] = result["admission_nonce_digest"]
	result["channel_key_sha256"] = nil
	result["channel_binding_sha256"] = nil
	return result
}
func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contract.CanonicalJSON(left)
	rightRaw, rightErr := contract.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}
func randomID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return encoded
}
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
