package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
	"github.com/cathedral-ai/cathedral-confidential-space/internal/supervisor"
)

const supervisorConfigSchema = "cathedral_cc_gpu_supervisor_config_v1"

const kbsRootCAPath = "/etc/cathedral/kbs-root.pem"

var (
	configSigningKeyID           string
	configSigningPublicKeyBase64 string
)

type inputConfig struct {
	Kind               string `json:"kind"`
	OwnerDigest        string `json:"owner_digest"`
	SealedReference    string `json:"sealed_reference"`
	SealedRecordSHA256 string `json:"sealed_record_sha256"`
	CiphertextSHA256   string `json:"ciphertext_sha256"`
	PlaintextSHA256    string `json:"plaintext_sha256"`
	CiphertextBytes    int64  `json:"ciphertext_bytes"`
	PlaintextBytes     int64  `json:"plaintext_bytes"`
	TargetPath         string `json:"target_path"`
}

type artifactConfig struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	MaxBytes int64  `json:"max_bytes"`
}

type runConfig struct {
	Schema                   string            `json:"schema"`
	ExecutionClass           string            `json:"execution_class"`
	ProfileID                string            `json:"profile_id"`
	ProjectID                string            `json:"project_id"`
	Zone                     string            `json:"zone"`
	ProviderResourceID       string            `json:"provider_resource_id"`
	ProviderInstanceID       string            `json:"provider_instance_id"`
	JobID                    string            `json:"job_id"`
	AttemptID                string            `json:"attempt_id"`
	JobContextDigest         string            `json:"job_context_digest"`
	AdmissionNonceDigest     string            `json:"admission_nonce_digest"`
	AttestationAudience      string            `json:"attestation_audience"`
	AdmissionChallengeBase64 string            `json:"admission_challenge_base64"`
	ProtectedInputs          []inputConfig     `json:"protected_inputs"`
	Command                  []string          `json:"command"`
	Artifacts                []artifactConfig  `json:"artifacts"`
	MaximumRuntimeSeconds    int64             `json:"maximum_runtime_seconds"`
	MaximumOutputBytes       int64             `json:"maximum_output_bytes"`
	GCSBucket                string            `json:"gcs_bucket"`
	GCSPrefix                string            `json:"gcs_prefix"`
	KBSOrigin                string            `json:"kbs_origin"`
	KBSServerName            string            `json:"kbs_server_name"`
	KBSRootCASHA256          string            `json:"kbs_root_ca_sha256"`
	TrustedKBSKeys           map[string]string `json:"trusted_kbs_keys"`
	TrustedKBSConfigSHA256   string            `json:"trusted_kbs_config_sha256"`
	KBSRegistrationAckBase64 string            `json:"kbs_registration_ack_base64"`
	KBSRegistrationAckSHA256 string            `json:"kbs_registration_ack_sha256"`
	NetworkPolicySHA256      string            `json:"network_policy_sha256"`
	ConfigSigningKeyID       string            `json:"config_signing_key_id"`
	ConfigSignature          map[string]any    `json:"config_signature"`
	IssuedAt                 string            `json:"issued_at"`
	ExpiresAt                string            `json:"expires_at"`
}

func loadRunConfig(raw []byte) (*runConfig, []byte, error) {
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return nil, nil, errors.New("supervisor config is empty or oversized")
	}
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document,
		"schema", "execution_class", "profile_id", "project_id", "zone", "provider_resource_id", "provider_instance_id", "job_id", "attempt_id", "job_context_digest", "admission_nonce_digest", "attestation_audience", "admission_challenge_base64", "protected_inputs", "command", "artifacts", "maximum_runtime_seconds", "maximum_output_bytes",
		"gcs_bucket", "gcs_prefix", "kbs_origin", "kbs_server_name", "kbs_root_ca_sha256", "trusted_kbs_keys", "trusted_kbs_config_sha256", "kbs_registration_ack_base64", "kbs_registration_ack_sha256", "network_policy_sha256",
		"config_signing_key_id", "config_signature", "issued_at", "expires_at",
	) {
		return nil, nil, errors.New("supervisor config has an invalid exact schema")
	}
	canonical, _ := contract.CanonicalJSON(document)
	var config runConfig
	if json.Unmarshal(canonical, &config) != nil || config.Schema != supervisorConfigSchema || config.ExecutionClass != "cc_gpu" || config.ProfileID != contract.ProfileID || !contract.ValidDigest(config.JobContextDigest) || !contract.ValidDigest(config.AdmissionNonceDigest) || !contract.ValidDigest(config.NetworkPolicySHA256) || !contract.ValidDigest(config.KBSRootCASHA256) || !contract.ValidDigest(config.TrustedKBSConfigSHA256) || !contract.ValidDigest(config.KBSRegistrationAckSHA256) {
		return nil, nil, errors.New("supervisor config values are invalid")
	}
	if err := verifyConfigSignature(document); err != nil {
		return nil, nil, err
	}
	issued, issuedErr := time.Parse("2006-01-02T15:04:05.000000Z", config.IssuedAt)
	expires, expiresErr := time.Parse("2006-01-02T15:04:05.000000Z", config.ExpiresAt)
	now := time.Now().UTC()
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > 10*time.Minute || now.Before(issued.Add(-30*time.Second)) || now.After(expires) {
		return nil, nil, errors.New("signed supervisor config is stale, future-dated, or overlong")
	}
	challenge, err := base64.StdEncoding.Strict().DecodeString(config.AdmissionChallengeBase64)
	if err != nil || len(challenge) == 0 || base64.StdEncoding.EncodeToString(challenge) != config.AdmissionChallengeBase64 {
		return nil, nil, errors.New("supervisor admission challenge is not canonical base64")
	}
	return &config, challenge, nil
}

func verifyKBSRegistrationAck(config *runConfig, challenge *contract.Challenge, trusted map[string]ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(config.KBSRegistrationAckBase64)
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || base64.StdEncoding.EncodeToString(raw) != config.KBSRegistrationAckBase64 || contract.Digest(raw) != config.KBSRegistrationAckSHA256 {
		return errors.New("KBS registration acknowledgment encoding or digest is invalid")
	}
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "schema", "job_id", "attempt_id", "job_context_digest", "owner_digest", "protected_input_set_digest", "sealed_record_sha256s", "job_record_sha256", "admin_client_certificate_sha256", "registered_at", "signing_key_id", "signature") || document["schema"] != "cathedral_cc_gpu_kbs_job_registration_ack_v1" || document["owner_digest"] != challenge.Expected["owner_digest"] || document["job_id"] != challenge.Expected["job_id"] || document["attempt_id"] != challenge.Expected["attempt_id"] || document["job_context_digest"] != challenge.Expected["job_context_digest"] || document["protected_input_set_digest"] != challenge.Expected["request"].(map[string]any)["protected_input_set_digest"] || !contract.ValidDigest(document["job_record_sha256"]) || !contract.ValidDigest(document["admin_client_certificate_sha256"]) {
		return errors.New("KBS registration acknowledgment does not bind the exact job record")
	}
	inputs := challenge.Expected["request"].(map[string]any)["protected_inputs"].([]any)
	digests, digestsOK := document["sealed_record_sha256s"].([]any)
	if !digestsOK || len(digests) != len(inputs) {
		return errors.New("KBS registration acknowledgment sealed-record set is invalid")
	}
	for index, rawInput := range inputs {
		if digests[index] != rawInput.(map[string]any)["sealed_record_sha256"] {
			return errors.New("KBS registration acknowledgment changed sealed-record ordering")
		}
	}
	registeredText, registeredOK := document["registered_at"].(string)
	registeredAt, timeErr := time.Parse("2006-01-02T15:04:05.000000Z", registeredText)
	configIssued, issuedErr := time.Parse("2006-01-02T15:04:05.000000Z", config.IssuedAt)
	if !registeredOK || timeErr != nil || issuedErr != nil || registeredAt.After(configIssued.Add(30*time.Second)) || configIssued.After(registeredAt.Add(10*time.Minute)) {
		return errors.New("KBS registration acknowledgment is stale or postdates supervisor config")
	}
	keyID, keyOK := document["signing_key_id"].(string)
	publicKey, trustedKey := trusted[keyID]
	signatureObject, signatureOK := document["signature"].(map[string]any)
	if !keyOK || !trustedKey || !signatureOK || !contract.ExactKeys(signatureObject, "algorithm", "value_base64") || signatureObject["algorithm"] != "ed25519" {
		return errors.New("KBS registration acknowledgment signing identity is untrusted")
	}
	signatureText, signatureTextOK := signatureObject["value_base64"].(string)
	signature, signatureErr := base64.StdEncoding.Strict().DecodeString(signatureText)
	if !signatureTextOK || signatureErr != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != signatureText {
		return errors.New("KBS registration acknowledgment signature is invalid")
	}
	unsigned := make(map[string]any, len(document)-1)
	for key, item := range document {
		if key != "signature" {
			unsigned[key] = item
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("KBS registration acknowledgment signature verification failed")
	}
	return nil
}

type gceIdentity struct {
	ProjectID  string
	Zone       string
	Name       string
	InstanceID string
}

func metadataValue(ctx context.Context, client *http.Client, suffix string) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/"+suffix, nil)
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	value := strings.TrimSpace(string(raw))
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" || readErr != nil || value == "" || len(value) > 4096 {
		return "", errors.New("GCE identity metadata is invalid")
	}
	return value, nil
}

func readGCEIdentity(ctx context.Context, client *http.Client) (gceIdentity, error) {
	projectID, projectErr := metadataValue(ctx, client, "project/project-id")
	zonePath, zoneErr := metadataValue(ctx, client, "instance/zone")
	name, nameErr := metadataValue(ctx, client, "instance/name")
	instanceID, idErr := metadataValue(ctx, client, "instance/id")
	zoneParts := strings.Split(zonePath, "/")
	if projectErr != nil || zoneErr != nil || nameErr != nil || idErr != nil || len(zoneParts) != 4 || zoneParts[2] != "zones" {
		return gceIdentity{}, errors.New("exact GCE workload identity metadata is unavailable")
	}
	return gceIdentity{ProjectID: projectID, Zone: zoneParts[3], Name: name, InstanceID: instanceID}, nil
}

func fetchRunConfig(ctx context.Context, identity gceIdentity, bucket, prefix string) ([]byte, error) {
	if bucket == "" || prefix == "" || strings.Contains(prefix, "..") {
		return nil, errors.New("attested static config bucket or prefix is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	httpClient := &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control redirects are forbidden") }}
	metadata := &supervisor.MetadataTokenSource{Client: &http.Client{Timeout: 10 * time.Second}}
	gcs, err := supervisor.NewProductionGCSClient(bucket, strings.Trim(prefix, "/")+"/configs/by-instance", httpClient, metadata)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		raw, readErr := gcs.Get(ctx, identity.Name+".json")
		if readErr == nil {
			return raw, nil
		}
		if !errors.Is(readErr, supervisor.ErrGCSObjectAbsent) {
			return nil, errors.New("immutable signed supervisor config read failed")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("immutable signed supervisor config did not appear within bootstrap deadline")
		case <-ticker.C:
		}
	}
}

func verifyConfigSignature(document map[string]any) error {
	if configSigningKeyID == "" || document["config_signing_key_id"] != configSigningKeyID {
		return errors.New("supervisor config signing key is not build pinned")
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(configSigningPublicKeyBase64)
	signature, ok := document["config_signature"].(map[string]any)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || !ok || !contract.ExactKeys(signature, "algorithm", "value_base64") || signature["algorithm"] != "ed25519" {
		return errors.New("supervisor config signature identity is invalid")
	}
	signatureText, signatureOK := signature["value_base64"].(string)
	if !signatureOK {
		return errors.New("supervisor config signature is invalid")
	}
	signatureRaw, err := base64.StdEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signatureRaw) != ed25519.SignatureSize {
		return errors.New("supervisor config signature is invalid")
	}
	unsigned := make(map[string]any, len(document)-1)
	for key, value := range document {
		if key != "config_signature" {
			unsigned[key] = value
		}
	}
	canonical, _ := contract.CanonicalJSON(unsigned)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signatureRaw) {
		return errors.New("supervisor config signature verification failed")
	}
	return nil
}

func runSupervisor(ctx context.Context) error {
	metadataClient := &http.Client{Timeout: 10 * time.Second}
	identity, err := readGCEIdentity(ctx, metadataClient)
	if err != nil {
		return err
	}
	raw, err := fetchRunConfig(ctx, identity, os.Getenv("CATHEDRAL_CONFIG_BUCKET"), os.Getenv("CATHEDRAL_CONFIG_PREFIX"))
	if err != nil {
		return err
	}
	config, challengeRaw, err := loadRunConfig(raw)
	if err != nil {
		return err
	}
	if config.ProjectID != identity.ProjectID || config.Zone != identity.Zone || config.ProviderResourceID != identity.Name || config.ProviderInstanceID != identity.InstanceID {
		return errors.New("signed supervisor config does not bind the exact GCE instance identity")
	}
	challenge, err := contract.ParseChallenge(challengeRaw, "admission")
	if err != nil {
		return err
	}
	if challenge.Expected["project_id"] != identity.ProjectID || challenge.Expected["zone"] != identity.Zone || challenge.Expected["provider_resource_id"] != identity.Name || challenge.Expected["provider_instance_id"] != identity.InstanceID {
		return errors.New("admission challenge differs from signed config and local GCE identity")
	}
	if config.JobID != challenge.Expected["job_id"] || config.AttemptID != challenge.Expected["attempt_id"] || config.JobContextDigest != challenge.Expected["job_context_digest"] || config.AdmissionNonceDigest != challenge.Expected["admission_nonce_digest"] || config.AttestationAudience != challenge.Expected["attestation_audience"] {
		return errors.New("signed supervisor config identity differs from admission challenge")
	}
	service, err := newServer("/usr/bin/nvidia-smi")
	if err != nil {
		return err
	}
	rootRaw, err := os.ReadFile(kbsRootCAPath)
	if err != nil || contract.Digest(rootRaw) != config.KBSRootCASHA256 {
		return errors.New("KBS root CA is unreadable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootRaw) {
		return errors.New("KBS root CA is invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: config.KBSServerName}
	kbs := supervisor.TLSKBSClient{Origin: config.KBSOrigin, TLSConfig: tlsConfig, Timeout: 90 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	httpClient := &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control redirects are forbidden") }}
	metadata := &supervisor.MetadataTokenSource{Client: &http.Client{Timeout: 10 * time.Second}}
	gcs, err := supervisor.NewProductionGCSClient(config.GCSBucket, config.GCSPrefix, httpClient, metadata)
	if err != nil {
		return err
	}
	control := &supervisor.GCSControlStore{GCS: gcs, JobID: challenge.Expected["job_id"].(string), AttemptID: challenge.Expected["attempt_id"].(string), JobContextDigest: challenge.Expected["job_context_digest"].(string), PollInterval: 2 * time.Second}
	cleanupKey := service.privateKey
	trustedKBS := map[string]ed25519.PublicKey{}
	for keyID, encoded := range config.TrustedKBSKeys {
		key, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if keyID == "" || decodeErr != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
			return errors.New("trusted KBS Ed25519 key is invalid")
		}
		trustedKBS[keyID] = ed25519.PublicKey(key)
	}
	if err := verifyKBSRegistrationAck(config, challenge, trustedKBS); err != nil {
		return err
	}
	inputs := make([]supervisor.ProtectedInput, len(config.ProtectedInputs))
	var protectedPlaintextBytes int64
	for index, input := range config.ProtectedInputs {
		inputs[index] = supervisor.ProtectedInput{Kind: input.Kind, OwnerDigest: input.OwnerDigest, SealedReference: input.SealedReference, SealedRecordSHA256: input.SealedRecordSHA256, CiphertextSHA256: input.CiphertextSHA256, PlaintextSHA256: input.PlaintextSHA256, CiphertextBytes: input.CiphertextBytes, PlaintextBytes: input.PlaintextBytes, TargetName: input.TargetPath}
		if input.PlaintextBytes < 1 || protectedPlaintextBytes > contract.MaxProtectedPlaintextBytes-input.PlaintextBytes {
			return errors.New("protected plaintext aggregate exceeds the first-profile bound")
		}
		protectedPlaintextBytes += input.PlaintextBytes
	}
	tmpfsBytes := protectedPlaintextBytes + config.MaximumOutputBytes + contract.ProtectedTmpfsReserveBytes
	artifacts := make([]supervisor.DeclaredArtifact, len(config.Artifacts))
	for index, artifact := range config.Artifacts {
		artifacts[index] = supervisor.DeclaredArtifact{Name: artifact.Path, Kind: artifact.Kind, MaxBytes: artifact.MaxBytes}
	}
	runner := &supervisor.Supervisor{
		Attestor: supervisor.KBSCompletionAttestor{KBS: kbs, Guest: service}, ChannelAttestor: service, KBS: kbs, Control: control, Inputs: gcs,
		Secrets: supervisor.LinuxTmpfsStore{BasePath: "/run/cathedral-cc-gpu/secrets", Bytes: tmpfsBytes},
		Sandbox: supervisor.LinuxSandbox{
			UnsharePath: "/usr/bin/unshare", SetprivPath: "/usr/bin/setpriv", IsolationHelperPath: "/opt/cathedral/bin/cathedral-confidential-space-collector",
			CgroupPath: "/sys/fs/cgroup/cathedral-cc-gpu/" + challenge.Expected["attempt_id"].(string), MemoryMaxBytes: 64 * 1024 * 1024 * 1024,
			PidsMax: 128, CPUQuotaMicros: 800000, AllowedEntrypoint: config.Command, PlatformNetworkPolicySHA256: config.NetworkPolicySHA256,
		},
		Outputs:    supervisor.AESGCMOutputStore{Uploader: gcs, Prefix: "gs://" + config.GCSBucket + "/" + config.GCSPrefix + "/outputs"},
		CleanupKey: cleanupKey, TrustedKBSKeys: trustedKBS, TrustedKBSConfigSHA256: config.TrustedKBSConfigSHA256,
		KBSRegistrationAckSHA256: config.KBSRegistrationAckSHA256,
	}
	_, err = runner.Run(ctx, supervisor.Request{AdmissionChallenge: challengeRaw, ProtectedInputs: inputs, Entrypoint: config.Command, DeclaredArtifacts: artifacts, MaximumRuntime: time.Duration(config.MaximumRuntimeSeconds) * time.Second, MaximumOutputBytes: config.MaximumOutputBytes})
	return err
}
