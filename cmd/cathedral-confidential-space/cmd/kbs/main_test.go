package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func validConfigDocument(t *testing.T) map[string]any {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return map[string]any{
		"schema": configSchema, "listen": "127.0.0.1:8443",
		"tls_certificate_path": filepath.Join(root, "tls.crt"), "tls_key_path": filepath.Join(root, "tls.key"),
		"signing_key_path": filepath.Join(root, "signing.key"), "signing_key_id": "kbs-1",
		"verifier_path": filepath.Join(root, "verifier"), "verifier_sha256": "sha256:" + string(bytes.Repeat([]byte("a"), 64)),
		"jobs_directory": filepath.Join(root, "jobs"), "admin_client_ca_path": filepath.Join(root, "admin-ca.pem"),
		"admin_client_ca_sha256": "sha256:" + string(bytes.Repeat([]byte("b"), 64)),
		"staging_authority_keys": map[string]any{"polaris-staging-1": base64.StdEncoding.EncodeToString(publicKey)},
	}
}

func writeConfig(t *testing.T, document map[string]any) string {
	t.Helper()
	raw, err := contract.CanonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kbs.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRequiresDedicatedStagingAuthorityKeys(t *testing.T) {
	document := validConfigDocument(t)
	configuration, err := loadConfig(writeConfig(t, document))
	if err != nil || len(configuration.StagingAuthorityKeys) != 1 {
		t.Fatal("valid dedicated staging authority key set was rejected")
	}
	delete(document, "staging_authority_keys")
	if _, err := loadConfig(writeConfig(t, document)); err == nil {
		t.Fatal("KBS config without staging authority keys was accepted")
	}
}

func TestLoadConfigRejectsInvalidStagingAuthorityKey(t *testing.T) {
	document := validConfigDocument(t)
	document["staging_authority_keys"] = map[string]any{"polaris-staging-1": base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))}
	if _, err := loadConfig(writeConfig(t, document)); err == nil {
		t.Fatal("KBS config accepted a malformed staging authority key")
	}
}
