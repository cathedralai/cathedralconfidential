package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
	"github.com/cathedral-ai/cathedral-confidential-space/internal/kbs"
)

const configSchema = "cathedral_cc_gpu_kbs_server_config_v1"

type config struct {
	Schema               string            `json:"schema"`
	Listen               string            `json:"listen"`
	TLSCertificate       string            `json:"tls_certificate_path"`
	TLSKey               string            `json:"tls_key_path"`
	SigningKey           string            `json:"signing_key_path"`
	SigningKeyID         string            `json:"signing_key_id"`
	VerifierPath         string            `json:"verifier_path"`
	VerifierSHA256       string            `json:"verifier_sha256"`
	JobsDirectory        string            `json:"jobs_directory"`
	AdminClientCAPath    string            `json:"admin_client_ca_path"`
	AdminClientCASHA256  string            `json:"admin_client_ca_sha256"`
	StagingAuthorityKeys map[string]string `json:"staging_authority_keys"`
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 {
		return nil, errors.New("KBS config is unreadable or oversized")
	}
	value, err := contract.StrictJSON(raw)
	document, ok := value.(map[string]any)
	if err != nil || !ok || !contract.ExactKeys(document, "schema", "listen", "tls_certificate_path", "tls_key_path", "signing_key_path", "signing_key_id", "verifier_path", "verifier_sha256", "jobs_directory", "admin_client_ca_path", "admin_client_ca_sha256", "staging_authority_keys") {
		return nil, errors.New("KBS config has an invalid exact schema")
	}
	canonical, _ := contract.CanonicalJSON(document)
	var result config
	if json.Unmarshal(canonical, &result) != nil || result.Schema != configSchema || result.Listen == "" || result.SigningKeyID == "" || !filepath.IsAbs(result.VerifierPath) || !filepath.IsAbs(result.JobsDirectory) || !contract.ValidDigest(result.VerifierSHA256) || !contract.ValidDigest(result.AdminClientCASHA256) || len(result.StagingAuthorityKeys) == 0 {
		return nil, errors.New("KBS config values are invalid")
	}
	for keyID, encoded := range result.StagingAuthorityKeys {
		key, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if keyID == "" || decodeErr != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
			return nil, errors.New("KBS staging authority key is invalid")
		}
	}
	return &result, nil
}

func securePath(path string, secret, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("KBS protected path is not absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("KBS protected path is absent, symlinked, or wrong type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 || secret && info.Mode().Perm()&0o077 != 0 {
		return errors.New("KBS protected path ownership or mode is unsafe")
	}
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		ancestorInfo, ancestorErr := os.Lstat(ancestor)
		if ancestorErr != nil || ancestorInfo.Mode()&os.ModeSymlink != 0 || !ancestorInfo.IsDir() || ancestorInfo.Mode().Perm()&0o022 != 0 {
			return errors.New("KBS protected path has a symlinked or writable ancestor")
		}
		if ancestor == filepath.Dir(ancestor) {
			break
		}
	}
	return nil
}

func staticVerifier(path, digest string) error {
	if err := securePath(path, false, false); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil || contract.Digest(raw) != digest {
		return errors.New("KBS verifier executable differs from configured digest")
	}
	file, err := elf.Open(path)
	if err != nil {
		return errors.New("KBS verifier is not an ELF executable")
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type == elf.PT_DYNAMIC || program.Type == elf.PT_INTERP {
			return errors.New("KBS verifier must be one static ELF without PT_DYNAMIC")
		}
	}
	return nil
}

func run(path string) error {
	if err := securePath(path, false, false); err != nil {
		return err
	}
	configuration, err := loadConfig(path)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path      string
		secret    bool
		directory bool
	}{{configuration.TLSCertificate, false, false}, {configuration.TLSKey, true, false}, {configuration.SigningKey, true, false}, {configuration.JobsDirectory, true, true}, {configuration.AdminClientCAPath, false, false}} {
		if err := securePath(item.path, item.secret, item.directory); err != nil {
			return err
		}
	}
	if err := staticVerifier(configuration.VerifierPath, configuration.VerifierSHA256); err != nil {
		return err
	}
	configRaw, _ := os.ReadFile(path)
	configDigest := contract.Digest(configRaw)
	adminCARaw, err := os.ReadFile(configuration.AdminClientCAPath)
	if err != nil || contract.Digest(adminCARaw) != configuration.AdminClientCASHA256 {
		return errors.New("KBS admin client CA differs from configured digest")
	}
	adminRoots := x509.NewCertPool()
	if !adminRoots.AppendCertsFromPEM(adminCARaw) {
		return errors.New("KBS admin client CA is invalid")
	}
	signingKey, err := os.ReadFile(configuration.SigningKey)
	if err != nil || len(signingKey) != ed25519.PrivateKeySize {
		return errors.New("KBS Ed25519 signing key is invalid")
	}
	defer func() {
		for index := range signingKey {
			signingKey[index] = 0
		}
	}()
	stagingAuthorityKeys := make(map[string]ed25519.PublicKey, len(configuration.StagingAuthorityKeys))
	for keyID, encoded := range configuration.StagingAuthorityKeys {
		key, _ := base64.StdEncoding.Strict().DecodeString(encoded)
		stagingAuthorityKeys[keyID] = ed25519.PublicKey(key)
	}
	service := &kbs.Server{
		Verifier: kbs.CommandVerifier{Path: configuration.VerifierPath, ExpectedSHA256: configuration.VerifierSHA256}, Jobs: kbs.JobStore{Directory: configuration.JobsDirectory},
		SigningKey: ed25519.PrivateKey(signingKey), SigningKeyID: configuration.SigningKeyID, ConfigSHA256: configDigest, StagingAuthorityKeys: stagingAuthorityKeys,
	}
	server := &http.Server{
		Addr: configuration.Listen, Handler: service, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: adminRoots},
	}
	return server.ListenAndServeTLS(configuration.TLSCertificate, configuration.TLSKey)
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "serve" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: cathedral-confidential-space-kbs serve CONFIG")
		os.Exit(2)
	}
	if err := run(os.Args[2]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "KBS stopped:", err)
		os.Exit(1)
	}
}
