package supervisor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	ReleaseRequestSchema = "cathedral_cc_gpu_kbs_release_request_v1"
	ReleaseAckSchema     = "cathedral_cc_gpu_kbs_release_ack_v1"
	ManifestSchema       = "cathedral_cc_gpu_output_manifest_v1"
	CleanupSchema        = "cathedral_cc_gpu_guest_cleanup_evidence_v1"
	maxArtifactBytes     = 64 * 1024 * 1024
	maximumWorkloadRun   = 2 * time.Hour
	finalizationGrace    = 10 * time.Minute
	sandboxShutdownGrace = 10 * time.Second
)

type ProtectedInput struct {
	Kind               string
	OwnerDigest        string
	SealedReference    string
	SealedRecordSHA256 string
	CiphertextSHA256   string
	PlaintextSHA256    string
	CiphertextBytes    int64
	PlaintextBytes     int64
	TargetName         string
}

type Request struct {
	AdmissionChallenge []byte
	ProtectedInputs    []ProtectedInput
	Entrypoint         []string
	DeclaredArtifacts  []DeclaredArtifact
	MaximumRuntime     time.Duration
	MaximumOutputBytes int64
}

type DeclaredArtifact struct {
	Name     string
	Kind     string
	MaxBytes int64
}

type AttestedEvidence struct {
	Canonical            []byte
	TokenSHA256          string
	ChannelKeySHA256     string
	ChannelBindingSHA256 string
	TLSEKMSHA256         string
}

type Attestor interface {
	Collect(context.Context, []byte) (AttestedEvidence, error)
}

type ChannelAttestor interface {
	CollectForEKM(context.Context, []byte, []byte) (AttestedEvidence, error)
}

type ReleaseRequest struct {
	Canonical []byte
	Document  map[string]any
}

type EncryptedItem struct {
	Kind               string
	OwnerDigest        string
	SealedReference    string
	SealedRecordSHA256 string
	CiphertextSHA256   string
	PlaintextSHA256    string
	CiphertextBytes    int64
	PlaintextBytes     int64
	NoncePrefix        []byte
	Key                []byte
}

type Release struct {
	AckCanonical      []byte
	ArtifactCanonical []byte
	Items             []EncryptedItem
	OutputKey         []byte
	Evidence          AttestedEvidence
}

// KBS must establish a mutually authenticated TLS 1.3 connection, derive its
// EKM, obtain CollectForEKM evidence on that same connection, and complete a
// one-time release without reconnecting. Implementations must fail if the TLS
// connection changes between challenge and encrypted response.
type KBS interface {
	Release(context.Context, ReleaseRequest, ChannelAttestor) (Release, error)
}

type Finalize struct {
	Challenge []byte
	Digest    string
}

type CompletionControl struct {
	Evidence          []byte
	ResultSHA256      string
	ManifestCanonical []byte
	FinalizeSHA256    string
}

type ControlStore interface {
	PublishAdmission(context.Context, []byte) error
	PublishRelease(context.Context, []byte, []byte, []byte) error
	PublishStatus(context.Context, string, map[string]any) error
	WaitFinalize(context.Context, string, string) (Finalize, error)
	PublishCompletion(context.Context, CompletionControl) error
	PublishCleanup(context.Context, []byte) error
	Cancellation(context.Context) <-chan struct{}
}

type SecretMount interface {
	Root() string
	PrepareForWorkload() error
	Close() error
}

type SecretStore interface {
	Mount(context.Context, string) (SecretMount, error)
}

type CiphertextStore interface {
	Open(context.Context, string) (io.ReadCloser, error)
}

type SandboxResult struct {
	ExitCode int
	Outputs  map[string][]byte
}

type sandboxCompletion struct {
	result SandboxResult
	err    error
}

// Sandbox must execute only the fixed digest-attested entrypoint as uid/gid
// 65532 with no_new_privs. Platform networking must already enforce the
// digest-bound control_plane_only endpoint set; the sandbox rejects a missing
// enforcement receipt rather than relying on application cooperation.
type Sandbox interface {
	VerifyIsolation(context.Context) error
	Run(context.Context, []string, string, int64) (SandboxResult, error)
}

type Supervisor struct {
	Attestor                 Attestor
	ChannelAttestor          ChannelAttestor
	KBS                      KBS
	Control                  ControlStore
	Secrets                  SecretStore
	Inputs                   CiphertextStore
	Sandbox                  Sandbox
	Outputs                  OutputStore
	CleanupKey               ed25519.PrivateKey
	TrustedKBSKeys           map[string]ed25519.PublicKey
	TrustedKBSConfigSHA256   string
	KBSRegistrationAckSHA256 string
	Now                      func() time.Time
}

type Outcome struct {
	ResultSHA256           string
	ArtifactManifestSHA256 string
	CompletionEvidence     []byte
	CleanupEvidence        []byte
}

func (supervisor *Supervisor) Run(ctx context.Context, request Request) (*Outcome, error) {
	if supervisor.Attestor == nil || supervisor.ChannelAttestor == nil || supervisor.KBS == nil || supervisor.Control == nil || supervisor.Secrets == nil || supervisor.Inputs == nil || supervisor.Sandbox == nil || supervisor.Outputs == nil || len(supervisor.CleanupKey) != ed25519.PrivateKeySize || len(supervisor.TrustedKBSKeys) == 0 || !contract.ValidDigest(supervisor.TrustedKBSConfigSHA256) || !contract.ValidDigest(supervisor.KBSRegistrationAckSHA256) {
		return nil, errors.New("supervisor production dependencies are incomplete")
	}
	if supervisor.Now == nil {
		supervisor.Now = time.Now
	}
	challenge, err := contract.ParseChallenge(request.AdmissionChallenge, "admission")
	if err != nil {
		return nil, err
	}
	if request.MaximumRuntime < time.Second || request.MaximumRuntime > maximumWorkloadRun || request.MaximumOutputBytes < 1 || request.MaximumOutputBytes > maxArtifactBytes || len(request.Entrypoint) != 2 || request.Entrypoint[0] != "/usr/bin/python3" || request.Entrypoint[1] != "/opt/cathedral/bin/cathedral-job" {
		return nil, errors.New("supervisor execution bounds are invalid")
	}
	for _, argument := range request.Entrypoint {
		if argument == "" || len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 {
			return nil, errors.New("supervisor fixed entrypoint is invalid")
		}
	}
	committedCommand, ok := challenge.Expected["request"].(map[string]any)["command"].([]any)
	entrypointValues := make([]any, len(request.Entrypoint))
	for index, value := range request.Entrypoint {
		entrypointValues[index] = value
	}
	if !ok || !canonicalEqual(committedCommand, entrypointValues) {
		return nil, errors.New("supervisor entrypoint differs from the exact job-committed command")
	}
	if err := validateDeclaredArtifacts(request.DeclaredArtifacts, challenge.Expected); err != nil {
		return nil, err
	}
	committedRequest := challenge.Expected["request"].(map[string]any)
	if !canonicalEqual(committedRequest["maximum_runtime_seconds"], int64(request.MaximumRuntime/time.Second)) || !canonicalEqual(committedRequest["maximum_output_bytes"], request.MaximumOutputBytes) {
		return nil, errors.New("runtime execution bounds differ from the exact job contract")
	}
	if err := validateProtectedInputs(request.ProtectedInputs, challenge.Expected); err != nil {
		return nil, err
	}
	attemptContext, cancelAttempt := context.WithTimeout(ctx, request.MaximumRuntime+finalizationGrace)
	defer cancelAttempt()
	if err := supervisor.Sandbox.VerifyIsolation(attemptContext); err != nil {
		return nil, errors.New("workload child isolation preflight failed before secret release")
	}
	releaseRequest, err := buildReleaseRequest(challenge)
	if err != nil {
		return nil, err
	}
	release, err := supervisor.KBS.Release(attemptContext, releaseRequest, supervisor.ChannelAttestor)
	admission := release.Evidence
	if err != nil || !validEvidence(admission) || len(release.AckCanonical) == 0 || len(release.ArtifactCanonical) == 0 || len(release.OutputKey) != 32 {
		return nil, errors.New("channel-bound one-time KBS release failed")
	}
	defer func() {
		zero(release.OutputKey)
		for index := range release.Items {
			zero(release.Items[index].Key)
		}
	}()
	if err := supervisor.verifyRelease(challenge, admission, releaseRequest, release); err != nil {
		zero(release.OutputKey)
		return nil, err
	}
	if err := supervisor.Control.PublishAdmission(attemptContext, admission.Canonical); err != nil {
		zero(release.OutputKey)
		return nil, errors.New("immutable admission publication failed")
	}
	if err := supervisor.Control.PublishRelease(attemptContext, releaseRequest.Canonical, release.AckCanonical, release.ArtifactCanonical); err != nil {
		zero(release.OutputKey)
		return nil, errors.New("immutable signed release publication failed")
	}
	mount, err := supervisor.Secrets.Mount(attemptContext, challenge.Expected["attempt_id"].(string))
	if err != nil {
		return nil, errors.New("protected tmpfs mount failed")
	}
	cleanupRequired := true
	defer func() {
		if cleanupRequired {
			_ = mount.Close()
		}
	}()
	if err := decryptInputs(attemptContext, supervisor.Inputs, mount.Root(), request.ProtectedInputs, release.Items); err != nil {
		zero(release.OutputKey)
		return nil, err
	}
	if err := mount.PrepareForWorkload(); err != nil {
		zero(release.OutputKey)
		return nil, errors.New("protected tmpfs ownership could not be narrowed to the workload uid")
	}
	if err := supervisor.Control.PublishStatus(attemptContext, "running", map[string]any{"release_ack_sha256": contract.Digest(release.AckCanonical), "kbs_registration_ack_sha256": supervisor.KBSRegistrationAckSHA256}); err != nil {
		return nil, errors.New("running status publication failed")
	}
	runContext, cancelRun := context.WithTimeout(attemptContext, request.MaximumRuntime)
	defer cancelRun()
	resultChannel := make(chan sandboxCompletion, 1)
	go func() {
		result, runErr := supervisor.Sandbox.Run(runContext, request.Entrypoint, mount.Root(), request.MaximumOutputBytes)
		resultChannel <- sandboxCompletion{result: result, err: runErr}
	}()
	var sandboxResult SandboxResult
	select {
	case <-supervisor.Control.Cancellation(runContext):
		cancelRun()
		terminated, ok := waitSandbox(resultChannel, sandboxShutdownGrace)
		if !ok {
			_ = supervisor.Control.PublishStatus(attemptContext, "failed", map[string]any{"reason": "sandbox_termination_unconfirmed"})
			return nil, errors.New("cancelled workload did not terminate within the fail-closed shutdown bound")
		}
		zeroSandboxOutputs(terminated.result.Outputs)
		_ = supervisor.Control.PublishStatus(attemptContext, "cancelled", map[string]any{})
		return nil, errors.New("workload cancelled by immutable control request")
	case completed := <-resultChannel:
		if completed.err != nil || completed.result.ExitCode != 0 {
			return nil, errors.New("fixed non-root workload failed")
		}
		sandboxResult = completed.result
	case <-runContext.Done():
		cancelRun()
		terminated, ok := waitSandbox(resultChannel, sandboxShutdownGrace)
		if !ok {
			_ = supervisor.Control.PublishStatus(attemptContext, "failed", map[string]any{"reason": "sandbox_termination_unconfirmed"})
			return nil, errors.New("bounded workload did not terminate within the fail-closed shutdown bound")
		}
		zeroSandboxOutputs(terminated.result.Outputs)
		return nil, errors.New("fixed non-root workload exceeded its bound")
	}
	defer zeroSandboxOutputs(sandboxResult.Outputs)
	stored, err := supervisor.Outputs.SealAndPublish(attemptContext, challenge, sandboxResult.Outputs, request.DeclaredArtifacts, release.OutputKey, request.MaximumOutputBytes)
	zero(release.OutputKey)
	zeroSandboxOutputs(sandboxResult.Outputs)
	if err != nil {
		return nil, err
	}
	resultDigest := stored.ResultSHA256
	manifestDigest := contract.Digest(stored.ManifestCanonical)
	if err := supervisor.Control.PublishStatus(attemptContext, "finalizing", map[string]any{"result_sha256": resultDigest, "artifact_manifest_sha256": manifestDigest}); err != nil {
		return nil, errors.New("result status publication failed")
	}
	finalize, err := supervisor.Control.WaitFinalize(attemptContext, resultDigest, manifestDigest)
	if err != nil || !contract.ValidDigest(finalize.Digest) {
		return nil, errors.New("immutable completion challenge is absent or mismatched")
	}
	completionChallenge, err := contract.ParseChallenge(finalize.Challenge, "completion")
	if err != nil || completionChallenge.FinalizeSHA256 != finalize.Digest || completionChallenge.Expected["result_sha256"] != strings.TrimPrefix(resultDigest, "sha256:") || completionChallenge.Expected["artifact_manifest_sha256"] != strings.TrimPrefix(manifestDigest, "sha256:") || completionChallenge.Expected["kbs_release_ack_sha256"] != strings.TrimPrefix(contract.Digest(release.AckCanonical), "sha256:") || completionChallenge.Expected["channel_key_sha256"] != admission.ChannelKeySHA256 || completionChallenge.Expected["channel_binding_sha256"] != admission.ChannelBindingSHA256 {
		return nil, errors.New("completion challenge does not bind the observed result and admission")
	}
	completion, err := supervisor.Attestor.Collect(attemptContext, finalize.Challenge)
	if err != nil || !validEvidence(completion) || completion.ChannelKeySHA256 != admission.ChannelKeySHA256 || completion.ChannelBindingSHA256 != admission.ChannelBindingSHA256 {
		return nil, errors.New("completion evidence failed or changed the attempt channel")
	}
	if err := supervisor.Control.PublishCompletion(attemptContext, CompletionControl{Evidence: completion.Canonical, ResultSHA256: resultDigest, ManifestCanonical: stored.ManifestCanonical, FinalizeSHA256: finalize.Digest}); err != nil {
		return nil, errors.New("immutable completion publication failed")
	}
	if err := mount.Close(); err != nil {
		return nil, errors.New("tmpfs zeroize and unmount failed")
	}
	cleanupRequired = false
	cleanupEvidence, err := supervisor.cleanupEvidence(challenge, admission, release.AckCanonical)
	if err != nil {
		return nil, err
	}
	if err := supervisor.Control.PublishCleanup(attemptContext, cleanupEvidence); err != nil {
		return nil, errors.New("signed guest cleanup publication failed")
	}
	return &Outcome{ResultSHA256: resultDigest, ArtifactManifestSHA256: manifestDigest, CompletionEvidence: completion.Canonical, CleanupEvidence: cleanupEvidence}, nil
}

func waitSandbox(result <-chan sandboxCompletion, maximum time.Duration) (sandboxCompletion, bool) {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	select {
	case completed := <-result:
		return completed, true
	case <-timer.C:
		return sandboxCompletion{}, false
	}
}

func zeroSandboxOutputs(outputs map[string][]byte) {
	for name := range outputs {
		zero(outputs[name])
		delete(outputs, name)
	}
}

func validEvidence(evidence AttestedEvidence) bool {
	return len(evidence.Canonical) > 0 && contract.ValidDigest(evidence.TokenSHA256) && contract.ValidHex(evidence.ChannelKeySHA256) && contract.ValidHex(evidence.ChannelBindingSHA256) && contract.ValidDigest(evidence.TLSEKMSHA256)
}

func validateProtectedInputs(inputs []ProtectedInput, expected map[string]any) error {
	if len(inputs) != 2 || inputs[0].Kind != "input" || inputs[0].TargetName != "input.bin" || inputs[1].Kind != "model" || inputs[1].TargetName != "model.bin" {
		return errors.New("first profile requires ordered input.bin and model.bin protected inputs")
	}
	seen := map[string]bool{}
	committed := make([]any, 0, len(inputs))
	var totalCiphertextBytes int64
	var totalPlaintextBytes int64
	for _, input := range inputs {
		if (input.Kind != "input" && input.Kind != "model") || input.OwnerDigest != expected["owner_digest"] || !contract.ValidDigest(input.OwnerDigest) || !contract.ValidDigest(input.SealedRecordSHA256) || !contract.ValidSealedReference(input.SealedReference, input.CiphertextSHA256) || !contract.ValidDigest(input.PlaintextSHA256) || input.CiphertextBytes < 1 || input.CiphertextBytes > contract.MaxProtectedCiphertextBytes || input.PlaintextBytes < 1 || input.PlaintextBytes > contract.MaxVectorPlaintextBytes || input.TargetName == "" || filepath.Base(input.TargetName) != input.TargetName || seen[input.TargetName] {
			return errors.New("protected input declaration is invalid or duplicated")
		}
		if totalCiphertextBytes > contract.MaxProtectedCiphertextBytes-input.CiphertextBytes || totalPlaintextBytes > contract.MaxProtectedPlaintextBytes-input.PlaintextBytes {
			return errors.New("protected input aggregate exceeds the first-profile bound")
		}
		totalCiphertextBytes += input.CiphertextBytes
		totalPlaintextBytes += input.PlaintextBytes
		seen[input.TargetName] = true
		committed = append(committed, map[string]any{
			"kind": input.Kind, "owner_digest": input.OwnerDigest, "sealed_reference": input.SealedReference,
			"sealed_record_sha256":     input.SealedRecordSHA256,
			"ciphertext_digest_sha256": input.CiphertextSHA256,
			"plaintext_digest_sha256":  input.PlaintextSHA256,
			"ciphertext_bytes":         input.CiphertextBytes, "plaintext_bytes": input.PlaintextBytes,
		})
	}
	request := expected["request"].(map[string]any)
	canonical, err := contract.CanonicalJSON(committed)
	if err != nil || request["protected_input_set_digest"] != contract.Digest(canonical) {
		return errors.New("runtime protected input declarations do not match the committed set digest")
	}
	if declared, present := request["protected_inputs"]; present {
		declaredCanonical, declaredErr := contract.CanonicalJSON(declared)
		if declaredErr != nil || !bytes.Equal(declaredCanonical, canonical) {
			return errors.New("runtime protected input declarations differ from the job contract")
		}
	}
	return nil
}

func validateDeclaredArtifacts(declarations []DeclaredArtifact, expected map[string]any) error {
	if len(declarations) != 1 || declarations[0].Name != "result.json" || declarations[0].Kind != "result" || declarations[0].MaxBytes != 262144 {
		return errors.New("declared output artifact set is empty or exceeds its bound")
	}
	seen := map[string]bool{}
	committed := make([]any, 0, len(declarations))
	for _, declaration := range declarations {
		if declaration.Name == "" || filepath.Base(declaration.Name) != declaration.Name || strings.ContainsAny(declaration.Name, "\\/\x00") || (declaration.Kind != "result" && declaration.Kind != "artifact") || declaration.MaxBytes < 1 || declaration.MaxBytes > maxArtifactBytes || seen[declaration.Name] {
			return errors.New("declared output artifact is invalid or duplicated")
		}
		seen[declaration.Name] = true
		committed = append(committed, map[string]any{"path": declaration.Name, "kind": declaration.Kind, "max_bytes": declaration.MaxBytes})
	}
	request := expected["request"].(map[string]any)
	if !canonicalEqual(request["artifacts"], committed) {
		return errors.New("runtime output declarations differ from the exact job contract")
	}
	return nil
}

func buildReleaseRequest(challenge *contract.Challenge) (ReleaseRequest, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ReleaseRequest{}, errors.New("KBS one-time nonce generation failed")
	}
	document := map[string]any{
		"schema": ReleaseRequestSchema, "job_id": challenge.Expected["job_id"], "attempt_id": challenge.Expected["attempt_id"],
		"job_context_digest":         challenge.Expected["job_context_digest"],
		"protected_input_set_digest": challenge.Expected["request"].(map[string]any)["protected_input_set_digest"],
		"one_time_nonce_digest":      contract.Digest(nonce),
	}
	canonical, err := contract.CanonicalJSON(document)
	return ReleaseRequest{Canonical: canonical, Document: document}, err
}

func (supervisor *Supervisor) verifyRelease(challenge *contract.Challenge, admission AttestedEvidence, request ReleaseRequest, release Release) error {
	policy, err := contract.ValidateReleasePolicy(release.ArtifactCanonical, challenge.Expected, supervisor.Now().UTC())
	if err != nil || verifyTrustedDocument(policy, supervisor.TrustedKBSKeys) != nil {
		return errors.New("KBS release policy is invalid, stale, or signed by an untrusted key")
	}
	value, err := contract.StrictJSON(release.AckCanonical)
	if err != nil {
		return errors.New("KBS release ack is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document,
		"schema", "grant_id", "job_id", "attempt_id", "job_context_digest", "channel_key_sha256",
		"channel_binding_sha256", "protected_input_set_digest", "admission_evidence_sha256",
		"admission_token_sha256", "tls_ekm_sha256", "one_time_nonce_digest", "grant_artifact_sha256", "issued_at", "expires_at",
		"release_request_sha256", "kbs_config_sha256", "single_use", "consumed_at", "signing_key_id", "signature",
	) || document["schema"] != ReleaseAckSchema || document["job_id"] != challenge.Expected["job_id"] || document["attempt_id"] != challenge.Expected["attempt_id"] || document["job_context_digest"] != challenge.Expected["job_context_digest"] || document["channel_key_sha256"] != admission.ChannelKeySHA256 || document["channel_binding_sha256"] != admission.ChannelBindingSHA256 || document["protected_input_set_digest"] != challenge.Expected["request"].(map[string]any)["protected_input_set_digest"] || document["admission_evidence_sha256"] != contract.Digest(admission.Canonical) || document["admission_token_sha256"] != admission.TokenSHA256 || document["tls_ekm_sha256"] != admission.TLSEKMSHA256 || document["one_time_nonce_digest"] != request.Document["one_time_nonce_digest"] || document["grant_artifact_sha256"] != contract.Digest(release.ArtifactCanonical) || document["single_use"] != true {
		return errors.New("KBS release ack is not bound to the exact one-time job/channel request")
	}
	if document["release_request_sha256"] != contract.Digest(request.Canonical) {
		return errors.New("KBS release ack does not commit the canonical one-time release request")
	}
	if document["kbs_config_sha256"] != supervisor.TrustedKBSConfigSHA256 {
		return errors.New("KBS release ack does not bind the trusted KBS config digest")
	}
	issued, err := parseTime(document["issued_at"])
	if err != nil {
		return err
	}
	expires, err := parseTime(document["expires_at"])
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute {
		return errors.New("KBS release ack lifetime is invalid")
	}
	consumed, err := parseTime(document["consumed_at"])
	now := supervisor.Now().UTC()
	if err != nil || consumed.Before(issued) || consumed.After(expires) || now.Before(issued.Add(-30*time.Second)) || now.After(expires.Add(30*time.Second)) {
		return errors.New("KBS release was not consumed once within its fresh lifetime")
	}
	keyID, ok := document["signing_key_id"].(string)
	publicKey, trusted := supervisor.TrustedKBSKeys[keyID]
	signatureObject, signatureOK := document["signature"].(map[string]any)
	if !ok || !trusted || !signatureOK || !contract.ExactKeys(signatureObject, "algorithm", "value_base64") || signatureObject["algorithm"] != "ed25519" {
		return errors.New("KBS release ack signing identity is invalid")
	}
	signatureText, ok := signatureObject["value_base64"].(string)
	if !ok {
		return errors.New("KBS release ack signature is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != signatureText {
		return errors.New("KBS release ack signature is invalid")
	}
	unsigned := make(map[string]any, len(document)-1)
	for key, item := range document {
		if key != "signature" {
			unsigned[key] = item
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("KBS release ack signature verification failed")
	}
	return nil
}

func verifyTrustedDocument(document map[string]any, trusted map[string]ed25519.PublicKey) error {
	keyID, keyOK := document["signing_key_id"].(string)
	publicKey, trustedKey := trusted[keyID]
	signatureObject, signatureOK := document["signature"].(map[string]any)
	if !keyOK || !trustedKey || !signatureOK || !contract.ExactKeys(signatureObject, "algorithm", "value_base64") || signatureObject["algorithm"] != "ed25519" {
		return errors.New("signed document identity is invalid")
	}
	signatureText, ok := signatureObject["value_base64"].(string)
	if !ok {
		return errors.New("signed document signature is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != signatureText {
		return errors.New("signed document signature is invalid")
	}
	unsigned := make(map[string]any, len(document)-1)
	for key, value := range document {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("signed document signature verification failed")
	}
	return nil
}

func parseTime(value any) (time.Time, error) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, errors.New("signed runtime time is invalid")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000Z", text)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000000Z") != text {
		return time.Time{}, errors.New("signed runtime time is not canonical UTC")
	}
	return parsed, nil
}

func decryptInputs(ctx context.Context, store CiphertextStore, root string, declarations []ProtectedInput, items []EncryptedItem) error {
	if len(items) != len(declarations) {
		return errors.New("KBS release item set is incomplete or duplicated")
	}
	byReference := map[string]EncryptedItem{}
	for _, item := range items {
		if _, exists := byReference[item.SealedReference]; exists {
			return errors.New("KBS release duplicated a sealed reference")
		}
		byReference[item.SealedReference] = item
	}
	for _, declaration := range declarations {
		item, present := byReference[declaration.SealedReference]
		if !present || item.Kind != declaration.Kind || item.OwnerDigest != declaration.OwnerDigest || item.SealedRecordSHA256 != declaration.SealedRecordSHA256 || item.CiphertextSHA256 != declaration.CiphertextSHA256 || item.PlaintextSHA256 != declaration.PlaintextSHA256 || item.CiphertextBytes != declaration.CiphertextBytes || item.PlaintextBytes != declaration.PlaintextBytes || len(item.Key) != 32 || len(item.NoncePrefix) != 8 {
			return errors.New("KBS encrypted item does not match the committed protected input")
		}
		block, err := aes.NewCipher(item.Key)
		if err != nil {
			return errors.New("KBS data key is invalid")
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return errors.New("KBS AEAD initialization failed")
		}
		reader, err := store.Open(ctx, declaration.SealedReference)
		if err != nil {
			zero(item.Key)
			return errors.New("immutable protected ciphertext could not be opened")
		}
		path := filepath.Join(root, declaration.TargetName)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = reader.Close()
			zero(item.Key)
			return errors.New("protected plaintext tmpfs file could not be created")
		}
		cipherHash := sha256.New()
		plainHash := sha256.New()
		counted := &countingReader{Reader: io.TeeReader(io.LimitReader(reader, declaration.CiphertextBytes+1), cipherHash)}
		var plaintextBytes int64
		for index := uint32(0); ; index++ {
			header := make([]byte, 4)
			_, readErr := io.ReadFull(counted, header)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				err = errors.New("chunked protected ciphertext framing is truncated")
				break
			}
			length := binary.BigEndian.Uint32(header)
			if length <= uint32(aead.Overhead()) || length > 4*1024*1024+uint32(aead.Overhead()) {
				err = errors.New("chunked protected ciphertext frame exceeds its bound")
				break
			}
			ciphertext := make([]byte, length)
			if _, readErr := io.ReadFull(counted, ciphertext); readErr != nil {
				err = errors.New("chunked protected ciphertext frame is truncated")
				break
			}
			nonce := make([]byte, 12)
			copy(nonce, item.NoncePrefix)
			binary.BigEndian.PutUint32(nonce[8:], index)
			// Ciphertext is deliberately job-independent so it can be sealed before
			// an attempt exists. The signed KBS sealed record binds this plaintext
			// commitment and AEAD stream to its immutable object digest/reference;
			// the one-time job record later binds that sealed record to the fresh
			// attested channel.
			aad, _ := contract.CanonicalJSON(map[string]any{"kind": declaration.Kind, "plaintext_sha256": declaration.PlaintextSHA256, "plaintext_bytes": declaration.PlaintextBytes, "chunk_index": index})
			plaintext, openErr := aead.Open(nil, nonce, ciphertext, aad)
			zero(ciphertext)
			if openErr != nil {
				err = errors.New("protected ciphertext chunk authentication failed")
				break
			}
			plaintextBytes += int64(len(plaintext))
			if plaintextBytes > declaration.PlaintextBytes {
				zero(plaintext)
				err = errors.New("protected plaintext exceeds its committed bound")
				break
			}
			_, _ = plainHash.Write(plaintext)
			if _, writeErr := file.Write(plaintext); writeErr != nil {
				zero(plaintext)
				err = errors.New("protected plaintext tmpfs write failed")
				break
			}
			zero(plaintext)
		}
		zero(item.Key)
		closeErr := reader.Close()
		fileErr := file.Close()
		cipherDigest := "sha256:" + hex.EncodeToString(cipherHash.Sum(nil))
		plainDigest := "sha256:" + hex.EncodeToString(plainHash.Sum(nil))
		if err != nil || closeErr != nil || fileErr != nil || counted.Count != declaration.CiphertextBytes || plaintextBytes != declaration.PlaintextBytes || cipherDigest != declaration.CiphertextSHA256 || plainDigest != declaration.PlaintextSHA256 {
			_ = os.Remove(path)
			return errors.New("protected input stream size, digest, framing, or decryption failed")
		}
	}
	return nil
}

type countingReader struct {
	Reader io.Reader
	Count  int64
}

func (reader *countingReader) Read(value []byte) (int, error) {
	count, err := reader.Reader.Read(value)
	reader.Count += int64(count)
	return count, err
}

func (supervisor *Supervisor) cleanupEvidence(challenge *contract.Challenge, admission AttestedEvidence, releaseAck []byte) ([]byte, error) {
	document := map[string]any{
		"schema": CleanupSchema, "job_id": challenge.Expected["job_id"], "attempt_id": challenge.Expected["attempt_id"],
		"job_context_digest": challenge.Expected["job_context_digest"], "channel_binding_sha256": admission.ChannelBindingSHA256,
		"release_ack_sha256": contract.Digest(releaseAck), "tmpfs_unmounted": true, "plaintext_paths_removed": true,
		"cleaned_at":     supervisor.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"signing_key_id": contract.HexDigest(supervisor.CleanupKey.Public().(ed25519.PublicKey)),
	}
	unsigned, err := contract.CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	document["signature"] = map[string]any{"algorithm": "ed25519", "value_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(supervisor.CleanupKey, unsigned))}
	return contract.CanonicalJSON(document)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contract.CanonicalJSON(left)
	rightRaw, rightErr := contract.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}
