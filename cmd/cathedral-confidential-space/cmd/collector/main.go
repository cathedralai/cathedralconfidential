// cathedral-confidential-space-collector runs inside the digest-pinned
// Confidential Space workload container. It never accepts an audience from a
// relying party: the workload-selected audience is injected at build time and
// attested as part of the container image.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
	"github.com/cathedral-ai/cathedral-confidential-space/internal/supervisor"
)

const (
	launcherSocket = "/run/container_launcher/teeserver.sock"
	tokenEndpoint  = "http://localhost/v1/token"
	tlsEKMLabel    = "EXPORTER-Cathedral-Confidential-Space-v1"
	maxTokenBytes  = 2 * 1024 * 1024
)

var workloadAudience string

type server struct {
	privateKey ed25519.PrivateKey
	client     *http.Client
	nvidiaSMI  string
}

func newServer(nvidiaSMI string) (*server, error) {
	if workloadAudience == "" || len(workloadAudience) > 512 || workloadAudience == "https://sts.google.com" {
		return nil, errors.New("workload-selected attestation audience was not pinned at build time")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("ephemeral attempt channel key creation failed")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", launcherSocket)
		},
		DisableKeepAlives: true,
	}
	return &server{
		privateKey: privateKey,
		client:     &http.Client{Transport: transport, Timeout: 45 * time.Second},
		nvidiaSMI:  nvidiaSMI,
	}, nil
}

func (service *server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/evidence" || request.URL.RawQuery != "" || request.TLS == nil {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, contract.MaxDocumentBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	tlsEKM, err := request.TLS.ExportKeyingMaterial(tlsEKMLabel, nil, 32)
	if err != nil {
		http.Error(response, "channel binding failed", http.StatusInternalServerError)
		return
	}
	evidence, err := service.collectForEKM(request.Context(), raw, tlsEKM)
	if err != nil {
		http.Error(response, "attestation evidence failed", http.StatusPreconditionFailed)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(evidence.Canonical)
}

func (service *server) collectForEKM(ctx context.Context, challengeRaw, tlsEKM []byte) (supervisor.AttestedEvidence, error) {
	challenge, err := contract.ParseChallenge(challengeRaw, "")
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("invalid challenge")
	}
	localGPU, err := service.inspectLocalGPU(ctx)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("local GPU is not Ready")
	}
	ready, err := contract.ReadyAssertion(challenge, service.privateKey.Public().(ed25519.PublicKey), localGPU)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("local GPU assertion rejected")
	}
	nonces, err := contract.TokenNonces(challenge, tlsEKM, ready)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("attestation binding failed")
	}
	token, err := service.requestToken(ctx, nonces)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("attestation service failed")
	}
	evidence, err := contract.SignedProof(challenge, token, nonces, ready, tlsEKM, service.privateKey)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("channel proof failed")
	}
	encoded, err := contract.CanonicalJSON(evidence)
	if err != nil {
		return supervisor.AttestedEvidence{}, errors.New("evidence encoding failed")
	}
	return supervisor.AttestedEvidence{Canonical: encoded, TokenSHA256: contract.Digest([]byte(token)), ChannelKeySHA256: ready["channel_key_sha256"].(string), ChannelBindingSHA256: ready["channel_binding_sha256"].(string), TLSEKMSHA256: contract.Digest(tlsEKM)}, nil
}

func (service *server) CollectForEKM(ctx context.Context, challenge, ekm []byte) (supervisor.AttestedEvidence, error) {
	return service.collectForEKM(ctx, challenge, ekm)
}

func (service *server) inspectLocalGPU(ctx context.Context) (contract.LocalGPU, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, service.nvidiaSMI,
		"--query-gpu=name,uuid", "--format=csv,noheader")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/nonexistent"}
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 64*1024 {
		return contract.LocalGPU{}, errors.New("local NVIDIA inventory failed")
	}
	lines := nonemptyLines(string(output))
	if len(lines) != 1 {
		return contract.LocalGPU{}, errors.New("exactly one local GPU is required")
	}
	fields := strings.Split(lines[0], ",")
	if len(fields) != 2 || !strings.Contains(strings.ToUpper(fields[0]), "H100") {
		return contract.LocalGPU{}, errors.New("local GPU is not H100")
	}
	uuid := strings.TrimSpace(fields[1])
	if !strings.HasPrefix(uuid, "GPU-") {
		return contract.LocalGPU{}, errors.New("local GPU UUID is invalid")
	}
	readyCommand := exec.CommandContext(ctx, service.nvidiaSMI, "conf-compute", "-grs")
	readyCommand.Env = command.Env
	readyOutput, err := readyCommand.Output()
	if err != nil || !readyState(string(readyOutput)) {
		return contract.LocalGPU{}, errors.New("local GPU ReadyState is not ready")
	}
	return contract.LocalGPU{Model: "NVIDIA H100 80GB", UUIDSHA256: contract.Digest([]byte(uuid)), Count: 1, Ready: true}, nil
}

func readyState(output string) bool {
	ready, notReady := 0, 0
	for _, line := range nonemptyLines(output) {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "not ready") {
			notReady++
		} else if strings.Contains(lower, "ready") && (strings.Contains(lower, "state") || strings.HasSuffix(lower, ": ready")) {
			ready++
		}
	}
	return ready == 1 && notReady == 0
}

func nonemptyLines(output string) []string {
	result := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

func (service *server) requestToken(ctx context.Context, nonces []string) (string, error) {
	body, err := contract.CanonicalJSON(map[string]any{
		"audience":   workloadAudience,
		"token_type": "PKI",
		"nonces":     stringSliceToAny(nonces),
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := service.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/jwt" && !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
		return "", errors.New("launcher did not return a PKI attestation token")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxTokenBytes {
		return "", errors.New("launcher token is empty or exceeds bounds")
	}
	token := strings.TrimSpace(string(raw))
	if len(strings.Split(token, ".")) != 3 || strings.ContainsAny(token, " \r\n\t") {
		return "", errors.New("launcher response is not one compact JWT")
	}
	return token, nil
}

func stringSliceToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "isolation-probe" {
		if err := runIsolationProbe(); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 6 && os.Args[1] == "sandbox-child" {
		if err := runSandboxChild(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "run" {
		if err := runSupervisor(context.Background()); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "confidential supervisor failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 8 || os.Args[1] != "serve" || os.Args[2] != "--listen" || os.Args[4] != "--tls-cert" || os.Args[6] != "--tls-key" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: collector run | collector serve --listen HOST:PORT --tls-cert PATH --tls-key PATH")
		os.Exit(2)
	}
	service, err := newServer("/usr/bin/nvidia-smi")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "collector startup failed:", err)
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr: os.Args[3], Handler: service,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	if err := httpServer.ListenAndServeTLS(os.Args[5], os.Args[7]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "collector stopped:", err)
		os.Exit(1)
	}
}
