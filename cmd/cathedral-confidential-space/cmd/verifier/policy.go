package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const policySchema = "cathedral_confidential_space_verifier_policy_v1"

var (
	policyManifestPath   string
	policyManifestSHA256 string
)

type containerPolicy struct {
	ImageDigest    string         `json:"image_digest"`
	ImageReference string         `json:"image_reference"`
	Args           []string       `json:"args"`
	Environment    map[string]any `json:"env"`
	RestartPolicy  string         `json:"restart_policy"`
}

type verifierPolicy struct {
	Schema                     string            `json:"schema"`
	ProfileID                  string            `json:"profile_id"`
	ProfileAuthority           string            `json:"profile_authority"`
	Audience                   string            `json:"audience"`
	RootCAPath                 string            `json:"root_ca_path"`
	RootCASHA256               string            `json:"root_ca_sha256"`
	ProjectID                  string            `json:"project_id"`
	Zone                       string            `json:"zone"`
	SourceImage                string            `json:"source_image"`
	WorkloadServiceAccount     string            `json:"workload_service_account"`
	AllowedInstanceNamePrefix  string            `json:"allowed_instance_name_prefix"`
	AllowedSWVersions          []string          `json:"allowed_swversions"`
	MinimumTDXTCBDate          string            `json:"minimum_tdx_tcb_date"`
	AllowedTDXTCBStatuses      []string          `json:"allowed_tdx_tcb_statuses"`
	AllowedNVIDIADrivers       []string          `json:"allowed_nvidia_drivers"`
	AllowedNVIDIAVBIOS         []string          `json:"allowed_nvidia_vbios"`
	TrustedKBSKeys             map[string]string `json:"trusted_kbs_keys"`
	TrustedKBSConfigSHA256     string            `json:"trusted_kbs_config_sha256"`
	TrustedDeletionKeys        map[string]string `json:"trusted_deletion_keys"`
	TrustedReceiptKeys         map[string]string `json:"trusted_receipt_keys"`
	Container                  containerPolicy   `json:"container"`
	MaxTokenAgeSeconds         int64             `json:"max_token_age_seconds"`
	MaxClockSkewSeconds        int64             `json:"max_clock_skew_seconds"`
	MaxDeletionAgeSeconds      int64             `json:"max_deletion_age_seconds"`
	MaxReleaseToReceiptSeconds int64             `json:"max_release_to_receipt_seconds"`
	ConfidentialSpaceRootCert  *x509.Certificate `json:"-"`
}

func loadPolicy() (*verifierPolicy, error) {
	if policyManifestPath == "" || !contract.ValidDigest(policyManifestSHA256) {
		return nil, errors.New("verifier policy manifest was not digest pinned at build time")
	}
	raw, err := os.ReadFile(policyManifestPath)
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || contract.Digest(raw) != policyManifestSHA256 {
		return nil, errors.New("verifier policy manifest is unreadable or mismatched")
	}
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return nil, errors.New("verifier policy manifest is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document,
		"schema", "profile_id", "profile_authority", "audience", "root_ca_path", "root_ca_sha256",
		"project_id", "zone", "source_image", "workload_service_account", "allowed_instance_name_prefix", "allowed_swversions", "minimum_tdx_tcb_date",
		"allowed_tdx_tcb_statuses", "allowed_nvidia_drivers", "allowed_nvidia_vbios", "trusted_kbs_keys", "trusted_kbs_config_sha256", "trusted_deletion_keys", "trusted_receipt_keys", "container",
		"max_token_age_seconds", "max_clock_skew_seconds", "max_deletion_age_seconds", "max_release_to_receipt_seconds",
	) {
		return nil, errors.New("verifier policy manifest has an invalid exact schema")
	}
	canonical, _ := contract.CanonicalJSON(document)
	var policy verifierPolicy
	if err := json.Unmarshal(canonical, &policy); err != nil {
		return nil, errors.New("verifier policy manifest cannot be decoded")
	}
	if policy.Schema != policySchema || policy.ProfileID != contract.ProfileID || policy.Audience == "" || len(policy.Audience) > 512 || policy.ProjectID == "" || policy.Zone != "us-central1-a" || policy.SourceImage == "" || policy.WorkloadServiceAccount == "" || policy.AllowedInstanceNamePrefix == "" || len(policy.AllowedInstanceNamePrefix) > 48 || !strings.HasPrefix(policy.AllowedInstanceNamePrefix, "cathedral-") || !strings.HasPrefix(policy.ProfileAuthority, "gpu-profile:"+contract.ProfileID+"@") {
		return nil, errors.New("verifier policy identity is invalid")
	}
	if !contract.ValidDigest(policy.RootCASHA256) || !contract.ValidDigest(policy.Container.ImageDigest) || !contract.ValidDigest(policy.TrustedKBSConfigSHA256) || policy.Container.ImageReference == "" || policy.Container.RestartPolicy != "Never" || len(policy.Container.Args) == 0 || len(policy.AllowedSWVersions) == 0 || len(policy.AllowedTDXTCBStatuses) == 0 || len(policy.AllowedNVIDIADrivers) == 0 || len(policy.AllowedNVIDIAVBIOS) == 0 || len(policy.TrustedKBSKeys) == 0 || len(policy.TrustedDeletionKeys) == 0 || len(policy.TrustedReceiptKeys) == 0 || policy.MaxTokenAgeSeconds < 1 || policy.MaxTokenAgeSeconds > 3600 || policy.MaxClockSkewSeconds < 0 || policy.MaxClockSkewSeconds > 300 || policy.MaxDeletionAgeSeconds < 1 || policy.MaxDeletionAgeSeconds > 24*60*60 || policy.MaxReleaseToReceiptSeconds < 1 || policy.MaxReleaseToReceiptSeconds > 24*60*60 {
		return nil, errors.New("verifier policy bounds are invalid")
	}
	for _, keys := range []map[string]string{policy.TrustedKBSKeys, policy.TrustedDeletionKeys, policy.TrustedReceiptKeys} {
		for keyID, encoded := range keys {
			key, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if keyID == "" || err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
				return nil, errors.New("verifier policy contains an invalid trusted Ed25519 key")
			}
		}
	}
	rootRaw, err := os.ReadFile(policy.RootCAPath)
	if err != nil || contract.Digest(rootRaw) != policy.RootCASHA256 {
		return nil, errors.New("stored Google Attestation PKI root does not match its policy pin")
	}
	block, rest := pem.Decode(rootRaw)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("stored Google Attestation PKI root is not one PEM certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA {
		return nil, errors.New("stored Google Attestation PKI root certificate is invalid")
	}
	fingerprint := sha256.Sum256(root.Raw)
	if hex.EncodeToString(fingerprint[:]) == strings.Repeat("0", 64) {
		return nil, errors.New("stored Google Attestation PKI root certificate is invalid")
	}
	policy.ConfidentialSpaceRootCert = root
	return &policy, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
