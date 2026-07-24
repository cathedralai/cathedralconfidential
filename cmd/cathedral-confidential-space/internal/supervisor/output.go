package supervisor

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

type OutputUploader interface {
	PutIfAbsent(context.Context, string, []byte, string) error
}

type StoredOutput struct {
	ResultSHA256      string
	ManifestCanonical []byte
}

type OutputStore interface {
	SealAndPublish(context.Context, *contract.Challenge, map[string][]byte, []DeclaredArtifact, []byte, int64) (StoredOutput, error)
}

type AESGCMOutputStore struct {
	Uploader OutputUploader
	Prefix   string
}

func (store AESGCMOutputStore) SealAndPublish(ctx context.Context, challenge *contract.Challenge, outputs map[string][]byte, declarations []DeclaredArtifact, key []byte, maximum int64) (StoredOutput, error) {
	if store.Uploader == nil || store.Prefix == "" || len(key) != 32 || len(outputs) == 0 || len(outputs) > 64 {
		return StoredOutput{}, errors.New("sealed immutable output store is not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return StoredOutput{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return StoredOutput{}, err
	}
	if len(outputs) != len(declarations) {
		return StoredOutput{}, errors.New("workload output set differs from the declared artifact set")
	}
	declared := map[string]DeclaredArtifact{}
	for _, declaration := range declarations {
		if _, exists := declared[declaration.Name]; exists {
			return StoredOutput{}, errors.New("declared artifact set is duplicated")
		}
		declared[declaration.Name] = declaration
	}
	names := make([]string, 0, len(outputs))
	var total int64
	for name, raw := range outputs {
		declaration, present := declared[name]
		if name == "" || filepath.Base(name) != name || len(raw) == 0 || !present || int64(len(raw)) > declaration.MaxBytes {
			return StoredOutput{}, errors.New("output artifact name or content is invalid")
		}
		total += int64(len(raw))
		if total > maximum {
			return StoredOutput{}, errors.New("output artifacts exceed their bound")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	artifacts := make([]any, 0, len(names))
	resultDigest := ""
	for _, name := range names {
		plaintext := outputs[name]
		declaration := declared[name]
		plainDigest := contract.Digest(plaintext)
		aad, _ := contract.CanonicalJSON(map[string]any{
			"job_context_digest": challenge.Expected["job_context_digest"], "attempt_id": challenge.Expected["attempt_id"],
			"path": name, "kind": declaration.Kind, "plaintext_sha256": plainDigest,
		})
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return StoredOutput{}, errors.New("output encryption nonce generation failed")
		}
		ciphertext := aead.Seal(nil, nonce, plaintext, aad)
		cipherDigest := contract.Digest(ciphertext)
		reference := store.Prefix + "/sha256/" + strings.TrimPrefix(cipherDigest, "sha256:") + ".aes256gcm"
		if err := store.Uploader.PutIfAbsent(ctx, reference, ciphertext, cipherDigest); err != nil {
			zero(ciphertext)
			return StoredOutput{}, errors.New("immutable sealed output upload failed")
		}
		zero(ciphertext)
		artifacts = append(artifacts, map[string]any{
			"path": name, "kind": declaration.Kind, "sealed_reference": reference, "ciphertext_sha256": cipherDigest,
			"plaintext_sha256": plainDigest, "byte_length": len(plaintext), "nonce_base64": base64.StdEncoding.EncodeToString(nonce),
			"aad_sha256": contract.Digest(aad),
		})
		if declaration.Kind == "result" {
			if resultDigest != "" {
				return StoredOutput{}, errors.New("output set contains multiple primary results")
			}
			resultDigest = plainDigest
		}
	}
	if resultDigest == "" {
		return StoredOutput{}, errors.New("output set has no declared primary result")
	}
	envelope, err := wrapOutputKey(challenge, key)
	if err != nil {
		return StoredOutput{}, err
	}
	manifest, err := contract.CanonicalJSON(map[string]any{
		"schema": ManifestSchema, "job_context_digest": challenge.Expected["job_context_digest"],
		"attempt_id": challenge.Expected["attempt_id"], "artifacts": artifacts, "output_key_envelope": envelope, "total_plaintext_bytes": total,
	})
	if err != nil {
		return StoredOutput{}, err
	}
	manifestReference := store.Prefix + "/manifest.json"
	if err := store.Uploader.PutIfAbsent(ctx, manifestReference, manifest, contract.Digest(manifest)); err != nil {
		return StoredOutput{}, errors.New("immutable output manifest upload failed")
	}
	return StoredOutput{ResultSHA256: resultDigest, ManifestCanonical: manifest}, nil
}

func wrapOutputKey(challenge *contract.Challenge, outputKey []byte) (map[string]any, error) {
	recipient := challenge.Expected["request"].(map[string]any)["output_recipient"].(map[string]any)
	encodedPublicKey := recipient["public_key_base64"].(string)
	publicKeyBytes, err := base64.StdEncoding.Strict().DecodeString(encodedPublicKey)
	if err != nil || len(publicKeyBytes) != 32 {
		return nil, errors.New("output recipient public key is invalid")
	}
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New("output recipient X25519 public key is invalid")
	}
	ephemeralPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("output key envelope ephemeral key generation failed")
	}
	shared, err := ephemeralPrivate.ECDH(publicKey)
	if err != nil {
		return nil, errors.New("output key envelope shared secret failed")
	}
	salt := sha256.Sum256([]byte(challenge.Expected["job_context_digest"].(string) + "\x00" + challenge.Expected["attempt_id"].(string)))
	info := []byte("cathedral-cc-gpu-output-key-wrap-v1\x00")
	wrappingKey := hkdfSHA256(shared, salt[:], info, 32)
	zero(shared)
	defer zero(wrappingKey)
	block, _ := aes.NewCipher(wrappingKey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("output key envelope nonce generation failed")
	}
	envelopeHeader := map[string]any{
		"schema": "cathedral_cc_gpu_output_key_envelope_v1", "algorithm": "x25519-hkdf-sha256-aes256gcm",
		"key_id": recipient["key_id"], "job_context_digest": challenge.Expected["job_context_digest"],
		"attempt_id": challenge.Expected["attempt_id"], "ephemeral_public_key_base64": base64.StdEncoding.EncodeToString(ephemeralPrivate.PublicKey().Bytes()),
	}
	aad, _ := contract.CanonicalJSON(envelopeHeader)
	wrapped := aead.Seal(nil, nonce, outputKey, aad)
	envelopeHeader["nonce_base64"] = base64.StdEncoding.EncodeToString(nonce)
	envelopeHeader["aad_sha256"] = contract.Digest(aad)
	envelopeHeader["wrapped_key_base64"] = base64.StdEncoding.EncodeToString(wrapped)
	return envelopeHeader, nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extractor := hmac.New(sha256.New, salt)
	_, _ = extractor.Write(secret)
	prk := extractor.Sum(nil)
	defer zero(prk)
	result := make([]byte, 0, length)
	previous := []byte{}
	for counter := byte(1); len(result) < length; counter++ {
		expander := hmac.New(sha256.New, prk)
		_, _ = expander.Write(previous)
		_, _ = expander.Write(info)
		_, _ = expander.Write([]byte{counter})
		previous = expander.Sum(nil)
		remaining := length - len(result)
		if remaining > len(previous) {
			remaining = len(previous)
		}
		result = append(result, previous[:remaining]...)
	}
	zero(previous)
	return result
}
