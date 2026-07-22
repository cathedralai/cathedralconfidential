package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func executableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func readBounded(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > int64(maximum) {
		return nil, errors.New("verifier artifact is not one bounded regular file")
	}
	return os.ReadFile(path)
}

func runPolaris(action string, input io.Reader, output io.Writer) error {
	phase := ""
	if action == "verify-admission" {
		phase = "admission"
	} else if action == "verify-completion" {
		phase = "completion"
	} else if action == "verify-release" {
		phase = "release"
	} else if action == "verify-launch-export" {
		phase = "launch-export"
	} else {
		return errors.New("invalid Polaris verifier action")
	}
	raw, err := io.ReadAll(io.LimitReader(input, contract.MaxDocumentBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > contract.MaxDocumentBytes {
		return errors.New("Polaris verifier input is empty or oversized")
	}
	policy, err := loadPolicy()
	if err != nil {
		return err
	}
	verifierDigest, err := executableDigest()
	if err != nil {
		return err
	}
	var verdict map[string]any
	if phase == "launch-export" {
		verdict, err = verifyLaunchExport(raw, policy, time.Now().UTC(), verifierDigest)
	} else if phase == "release" {
		verdict, err = verifyReleaseInput(raw, policy, time.Now().UTC(), verifierDigest)
	} else {
		verdict, err = verifyInput(raw, phase, policy, time.Now().UTC(), verifierDigest)
	}
	if err != nil {
		return err
	}
	encoded, _ := contract.CanonicalJSON(verdict)
	_, err = output.Write(encoded)
	return err
}

type receiptArgs struct {
	phase, bundle, cpu, gpu, identity, grant, deletion, receipt, result string
}

func parseReceiptArgs(args []string) (*receiptArgs, error) {
	if len(args) != 19 || args[0] != "verify-receipt" {
		return nil, errors.New("invalid receipt verifier command")
	}
	wanted := []string{"--phase", "--bundle", "--cpu-evidence", "--gpu-evidence", "--gpu-identity-set", "--secret-release-grant", "--deletion-evidence", "--receipt", "--result"}
	values := make([]string, len(wanted))
	for index, flag := range wanted {
		position := 1 + index*2
		if args[position] != flag || args[position+1] == "" {
			return nil, errors.New("receipt verifier arguments are invalid")
		}
		values[index] = args[position+1]
	}
	if values[0] != "admission" && values[0] != "completion" {
		return nil, errors.New("receipt verifier phase is invalid")
	}
	return &receiptArgs{phase: values[0], bundle: values[1], cpu: values[2], gpu: values[3], identity: values[4], grant: values[5], deletion: values[6], receipt: values[7], result: values[8]}, nil
}

func runReceipt(args []string) error {
	parsed, err := parseReceiptArgs(args)
	if err != nil {
		return err
	}
	policy, err := loadPolicy()
	if err != nil {
		return err
	}
	verifierDigest, err := executableDigest()
	if err != nil {
		return err
	}
	bundle, err := readBounded(parsed.bundle, contract.MaxDocumentBytes)
	if err != nil {
		return err
	}
	bundleValue, err := contract.StrictJSON(bundle)
	if err != nil {
		return errors.New("replay bundle is not strict JSON")
	}
	replay, ok := bundleValue.(map[string]any)
	if !ok || !contract.ExactKeys(replay, "schema", "phase", "expected", "evidence", "tls_ekm_sha256", "finalize_sha256") || replay["schema"] != "cathedral_confidential_space_replay_bundle_v1" || replay["phase"] != parsed.phase {
		return errors.New("replay bundle has an invalid exact schema")
	}
	verifierInput := map[string]any{"expected": replay["expected"], "evidence": replay["evidence"], "tls_ekm_sha256": replay["tls_ekm_sha256"], "finalize_sha256": replay["finalize_sha256"]}
	inputRaw, _ := contract.CanonicalJSON(verifierInput)
	verdict, err := verifyInput(inputRaw, parsed.phase, policy, time.Now().UTC(), verifierDigest)
	if err != nil {
		return err
	}
	artifacts := verdict["evidence_artifacts"].(map[string]any)
	for path, key := range map[string]string{parsed.bundle: "bundle", parsed.cpu: "cpu_evidence", parsed.gpu: "gpu_evidence", parsed.identity: "gpu_identity_set"} {
		observed, err := readBounded(path, contract.MaxDocumentBytes)
		if err != nil {
			return err
		}
		expected, err := base64.StdEncoding.Strict().DecodeString(artifacts[key].(string))
		if err != nil || !bytes.Equal(observed, expected) {
			return errors.New("stored replay artifact differs from re-verified token claims")
		}
	}
	receiptRaw, err := readBounded(parsed.receipt, contract.MaxDocumentBytes)
	if err != nil {
		return err
	}
	receiptValue, err := contract.StrictJSON(receiptRaw)
	if err != nil {
		return errors.New("receipt is not strict JSON")
	}
	receipt, ok := receiptValue.(map[string]any)
	if !ok || !contract.ExactKeys(receipt, launchReceiptKeys...) || receipt["schema"] != "cathedral_cc_gpu_job_receipt_v1" || receipt["execution_class"] != "cc_gpu" || receipt["profile_id"] != contract.ProfileID || receipt["provider"] != "gcp" || receipt["machine_type"] != "a3-highgpu-1g" || receipt["zone"] != "us-central1-a" || receipt["cpu_tee"] != "intel_tdx" || receipt["gpu_model"] != "nvidia_h100_80gb" || receipt["provisioning_model"] != "spot" || receipt["job_context_digest"] != verdict["job_context_digest"] || receipt["subject_hotkey"] != verdict["subject_hotkey"] || receipt["channel_binding_digest"] != "sha256:"+verdict["channel_binding_sha256"].(string) || receipt[parsed.phase+"_nonce_digest"] != verdict["nonce_digest"] || receipt[parsed.phase+"_bundle_digest"] != contract.Digest(bundle) {
		return errors.New("receipt does not bind the re-verified Confidential Space evidence")
	}
	if err := verifySignedArtifact(receipt, policy.TrustedReceiptKeys); err != nil {
		return err
	}
	for _, key := range []string{"worker_id", "job_id", "attempt_id", "profile_authority"} {
		if receipt[key] != verdict[key] {
			return errors.New("receipt identity differs from re-verified Confidential Space evidence")
		}
	}
	if receipt[parsed.phase+"_cpu_evidence_digest"] != "sha256:"+verdict["cpu_evidence_sha256"].(string) || receipt[parsed.phase+"_gpu_evidence_digest"] != "sha256:"+verdict["gpu_evidence_sha256"].(string) || receipt[parsed.phase+"_gpu_identity_set_digest"] != "sha256:"+verdict["gpu_identity_set_sha256"].(string) {
		return errors.New("receipt evidence digests differ from re-verified token claims")
	}
	grant, err := readBounded(parsed.grant, contract.MaxDocumentBytes)
	if err != nil || receipt["secret_release_grant_digest"] != contract.Digest(grant) {
		return errors.New("receipt release-grant artifact digest is mismatched")
	}
	deletion, err := readBounded(parsed.deletion, contract.MaxDocumentBytes)
	if err != nil || receipt["deletion_evidence_digest"] != contract.Digest(deletion) || receipt["deletion_confirmed"] != true {
		return errors.New("receipt deletion artifact digest is mismatched")
	}
	expected := replay["expected"].(map[string]any)
	if err := verifyReleaseGrant(grant, receipt, expected, replay["evidence"].(map[string]any), replay["tls_ekm_sha256"].(string), policy, time.Now().UTC()); err != nil {
		return err
	}
	if err := verifyDeletion(deletion, receipt, expected, policy, time.Now().UTC()); err != nil {
		return err
	}
	cpu, _ := readBounded(parsed.cpu, contract.MaxDocumentBytes)
	gpu, _ := readBounded(parsed.gpu, contract.MaxDocumentBytes)
	identity, _ := readBounded(parsed.identity, contract.MaxDocumentBytes)
	result := map[string]any{
		"ok": false, "cpu_measurement_digest": contract.Digest(cpu), "gpu_measurement_digest": contract.Digest(gpu),
		"cpu_nonce_digest": receipt[parsed.phase+"_nonce_digest"], "gpu_nonce_digest": receipt[parsed.phase+"_nonce_digest"],
		"job_context_digest": receipt["job_context_digest"], "subject_hotkey": receipt["subject_hotkey"],
		"channel_binding_digest": receipt["channel_binding_digest"], "gpu_identity_set_digest": contract.Digest(identity),
		"same_guest": true, "gpu_cc_mode_enabled": true, "gpu_ready_state": true,
		"measurement_policy_ok": true, "runtime_isolation_ok": true,
		"secret_release_grant_digest": contract.Digest(grant), "secret_release_signature_verified": true, "secret_release_semantics_verified": true,
		"deletion_evidence_digest": contract.Digest(deletion), "deletion_signature_verified": true, "deletion_semantics_verified": true,
		"provider_absent": true, "reason": "verified fixed first-party runtime isolation and evidence chain",
	}
	result["ok"] = true
	encoded, _ := contract.CanonicalJSON(result)
	if filepath.Clean(parsed.result) != parsed.result {
		return errors.New("result path is not clean")
	}
	file, err := os.OpenFile(parsed.result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "verify-admission" || os.Args[1] == "verify-release" || os.Args[1] == "verify-completion" || os.Args[1] == "verify-launch-export") {
		if err := runPolaris(os.Args[1], os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Confidential Space verification failed:", err)
			os.Exit(1)
		}
		return
	}
	if err := runReceipt(os.Args[1:]); err != nil {
		// Validator mode intentionally emits no stdout or stderr. The loader only
		// trusts the O_EXCL canonical result file and the process exit status.
		os.Exit(1)
	}
}
