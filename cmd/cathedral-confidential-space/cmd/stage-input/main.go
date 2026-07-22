package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
	"github.com/cathedral-ai/cathedral-confidential-space/internal/staging"
)

func run(arguments []string) error {
	flags := flag.NewFlagSet("stage-input", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	input := flags.String("input", "", "absolute plaintext file path")
	kind := flags.String("kind", "", "fixed-profile input or model vector")
	bucket := flags.String("bucket", "", "GCS bucket")
	prefix := flags.String("prefix", "", "tenant-scoped GCS prefix")
	temporary := flags.String("temp-dir", "", "local directory for bounded ciphertext staging")
	gcloud := flags.String("gcloud", "", "absolute non-symlink operator-trusted gcloud executable path for ADC")
	polarisOrigin := flags.String("polaris-origin", "", "same-origin Polaris HTTPS API origin")
	polarisToken := flags.String("polaris-api-token-file", "", "0600 non-symlink file containing the Polaris bearer token")
	stagingAuthorityKeyID := flags.String("staging-authority-key-id", "", "trusted Polaris staging-authority Ed25519 key ID")
	stagingAuthorityPublicKey := flags.String("staging-authority-public-key-base64", "", "trusted Polaris staging-authority Ed25519 public key")
	kbsOrigin := flags.String("kbs-origin", "", "KBS HTTPS origin")
	kbsServerName := flags.String("kbs-server-name", "", "KBS TLS server name")
	kbsRoot := flags.String("kbs-root-ca", "", "KBS root CA PEM")
	kbsSigningKeyID := flags.String("kbs-signing-key-id", "", "trusted KBS Ed25519 signing key ID")
	kbsSigningPublicKey := flags.String("kbs-signing-public-key-base64", "", "trusted KBS Ed25519 public key")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid stage-input arguments")
	}
	polaris, err := staging.NewProductionPolarisClient(*polarisOrigin, *polarisToken, *stagingAuthorityKeyID, *stagingAuthorityPublicKey)
	if err != nil {
		return err
	}
	defer polaris.Close()
	kbs, err := staging.NewProductionKBSClient(*kbsOrigin, *kbsServerName, *kbsRoot, *kbsSigningKeyID, *kbsSigningPublicKey)
	if err != nil {
		return err
	}
	gcs := staging.NewProductionGCSClient(staging.GcloudTokenSource{Path: *gcloud})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	declaration, err := staging.Stage(ctx, staging.Options{InputPath: *input, Kind: *kind, Bucket: *bucket, Prefix: *prefix, TempDir: *temporary, GCS: gcs, Polaris: polaris, KBS: kbs})
	if err != nil {
		return err
	}
	value := map[string]any{
		"kind": declaration.Kind, "sealed_reference": declaration.SealedReference, "sealed_record_sha256": declaration.SealedRecordSHA256,
		"ciphertext_digest_sha256": declaration.CiphertextDigestSHA256, "plaintext_digest_sha256": declaration.PlaintextDigestSHA256,
		"ciphertext_bytes": declaration.CiphertextBytes, "plaintext_bytes": declaration.PlaintextBytes,
	}
	encoded, err := contract.CanonicalJSON(value)
	if err != nil || len(encoded) == 0 || len(encoded) > 64*1024 || base64.StdEncoding.EncodeToString(kbs.SigningPublicKey) != *kbsSigningPublicKey {
		return errors.New("staged declaration could not be encoded")
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "protected-input staging failed:", err)
		os.Exit(1)
	}
}
