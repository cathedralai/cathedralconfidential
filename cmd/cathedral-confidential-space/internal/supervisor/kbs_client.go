package supervisor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

const (
	kbsChallengeSchema        = contract.KBSChallengeSchema
	kbsResponseSchema         = contract.KBSReleaseResponseSchema
	kbsChallengeRequestSchema = contract.KBSChallengeRequestSchema
	kbsReleaseSubmitSchema    = contract.KBSReleaseSubmitSchema
	kbsCompletionStart        = contract.KBSCompletionStartSchema
	kbsCompletionAck          = contract.KBSCompletionAckSchema
)

type TLSKBSClient struct {
	Origin    string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

type KBSCompletionAttestor struct {
	KBS   TLSKBSClient
	Guest ChannelAttestor
}

func (attestor KBSCompletionAttestor) Collect(ctx context.Context, challenge []byte) (AttestedEvidence, error) {
	return attestor.KBS.AttestCompletion(ctx, challenge, attestor.Guest)
}

func (client TLSKBSClient) AttestCompletion(ctx context.Context, challenge []byte, attestor ChannelAttestor) (AttestedEvidence, error) {
	if attestor == nil || client.TLSConfig == nil || client.TLSConfig.RootCAs == nil || len(client.TLSConfig.Certificates) != 0 || client.TLSConfig.ServerName == "" || client.TLSConfig.MinVersion != tls.VersionTLS13 || client.TLSConfig.MaxVersion != tls.VersionTLS13 {
		return AttestedEvidence{}, errors.New("completion relying-party TLS client is not fail-closed configured")
	}
	parsed, err := contract.ParseChallenge(challenge, "completion")
	if err != nil {
		return AttestedEvidence{}, err
	}
	origin, err := url.Parse(client.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.User != nil {
		return AttestedEvidence{}, errors.New("KBS origin is not one canonical HTTPS origin")
	}
	requestContext, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()
	var lock sync.Mutex
	var established net.Conn
	tlsDialer := tls.Dialer{Config: client.TLSConfig.Clone(), NetDialer: &net.Dialer{Timeout: 10 * time.Second}}
	transport := &http.Transport{ForceAttemptHTTP2: false, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: client.Timeout,
		DialTLSContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			lock.Lock()
			defer lock.Unlock()
			if established != nil {
				return nil, errors.New("KBS attempted to replace the completion EKM connection")
			}
			connection, dialErr := tlsDialer.DialContext(dialContext, network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			tlsConnection, ok := connection.(*tls.Conn)
			if !ok || tlsConnection.ConnectionState().Version != tls.VersionTLS13 || len(tlsConnection.ConnectionState().VerifiedChains) == 0 {
				_ = connection.Close()
				return nil, errors.New("KBS completion connection is not verified TLS 1.3")
			}
			established = connection
			return connection, nil
		},
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("KBS redirects are forbidden") }}
	startBody, _ := contract.CanonicalJSON(map[string]any{"schema": kbsCompletionStart, "challenge_base64": base64.StdEncoding.EncodeToString(challenge), "challenge_sha256": parsed.Digest})
	startResponse, connection, err := kbsRequest(requestContext, httpClient, nil, client.Origin+"/v1/attestations/completion/challenge", startBody)
	if err != nil {
		return AttestedEvidence{}, err
	}
	startValue, parseErr := contract.StrictJSON(startResponse)
	start, ok := startValue.(map[string]any)
	if parseErr != nil || !ok || !contract.ExactKeys(start, "schema", "challenge_sha256", "accepted") || start["schema"] != kbsCompletionStart || start["challenge_sha256"] != parsed.Digest || start["accepted"] != true {
		return AttestedEvidence{}, errors.New("KBS completion challenge acknowledgment is invalid")
	}
	tlsConnection := connection.(*tls.Conn)
	state := tlsConnection.ConnectionState()
	ekm, err := state.ExportKeyingMaterial("EXPORTER-Cathedral-CC-GPU-KBS-v1", nil, 32)
	if err != nil {
		return AttestedEvidence{}, errors.New("KBS completion EKM derivation failed")
	}
	evidence, err := attestor.CollectForEKM(requestContext, challenge, ekm)
	zero(ekm)
	if err != nil || !validEvidence(evidence) {
		return AttestedEvidence{}, errors.New("completion Confidential Space evidence failed")
	}
	evidenceValue, _ := contract.StrictJSON(evidence.Canonical)
	body, _ := contract.CanonicalJSON(map[string]any{"schema": kbsCompletionAck, "job_id": parsed.Expected["job_id"], "attempt_id": parsed.Expected["attempt_id"], "challenge_sha256": parsed.Digest, "evidence": evidenceValue})
	ackResponse, ackConnection, err := kbsRequest(requestContext, httpClient, connection, client.Origin+"/v1/attestations/completion", body)
	if errors.Is(err, errKBSResponseUncertain) && ackConnection == connection {
		ackResponse, ackConnection, err = kbsRequest(requestContext, httpClient, connection, client.Origin+"/v1/attestations/completion", body)
	}
	if err != nil || ackConnection != connection {
		return AttestedEvidence{}, errors.New("KBS completion verification changed the EKM-bound connection")
	}
	ackValue, parseErr := contract.StrictJSON(ackResponse)
	ack, ok := ackValue.(map[string]any)
	if parseErr != nil || !ok || !contract.ExactKeys(ack, "schema", "challenge_sha256", "evidence_sha256", "verified") || ack["schema"] != kbsCompletionAck || ack["challenge_sha256"] != parsed.Digest || ack["evidence_sha256"] != contract.Digest(evidence.Canonical) || ack["verified"] != true {
		return AttestedEvidence{}, errors.New("KBS did not independently verify completion evidence")
	}
	return evidence, nil
}

func (client TLSKBSClient) Release(ctx context.Context, request ReleaseRequest, attestor ChannelAttestor) (Release, error) {
	if attestor == nil || client.TLSConfig == nil || client.TLSConfig.RootCAs == nil || len(client.TLSConfig.Certificates) != 0 || client.TLSConfig.ServerName == "" || client.TLSConfig.MinVersion != tls.VersionTLS13 || client.TLSConfig.MaxVersion != tls.VersionTLS13 || client.Timeout < time.Second || client.Timeout > 2*time.Minute {
		return Release{}, errors.New("KBS server-authenticated TLS 1.3 client is not fail-closed configured")
	}
	origin, err := url.Parse(client.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.User != nil {
		return Release{}, errors.New("KBS origin is not one canonical HTTPS origin")
	}
	requestContext, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()
	var lock sync.Mutex
	var established net.Conn
	tlsDialer := tls.Dialer{Config: client.TLSConfig.Clone(), NetDialer: &net.Dialer{Timeout: 10 * time.Second}}
	transport := &http.Transport{
		ForceAttemptHTTP2: false, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
		IdleConnTimeout: client.Timeout,
		DialTLSContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			lock.Lock()
			defer lock.Unlock()
			if established != nil {
				return nil, errors.New("KBS attempted to replace the EKM-bound TLS connection")
			}
			connection, err := tlsDialer.DialContext(dialContext, network, address)
			if err != nil {
				return nil, err
			}
			tlsConnection, ok := connection.(*tls.Conn)
			if !ok || tlsConnection.ConnectionState().Version != tls.VersionTLS13 || !tlsConnection.ConnectionState().HandshakeComplete || len(tlsConnection.ConnectionState().VerifiedChains) == 0 {
				_ = connection.Close()
				return nil, errors.New("KBS connection is not verified server-authenticated TLS 1.3")
			}
			established = connection
			return connection, nil
		},
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("KBS redirects are forbidden") }}
	challengeRequest, err := contract.CanonicalJSON(map[string]any{"schema": kbsChallengeRequestSchema, "request": request.Document})
	if err != nil {
		return Release{}, err
	}
	challengeResponse, connection, err := kbsRequest(requestContext, httpClient, nil, client.Origin+"/v1/releases/challenge", challengeRequest)
	if err != nil {
		return Release{}, err
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return Release{}, errors.New("KBS challenge did not use TLS")
	}
	connectionState := tlsConnection.ConnectionState()
	ekm, err := connectionState.ExportKeyingMaterial("EXPORTER-Cathedral-CC-GPU-KBS-v1", nil, 32)
	if err != nil {
		return Release{}, errors.New("KBS TLS EKM derivation failed")
	}
	challengeValue, err := contract.StrictJSON(challengeResponse)
	if err != nil {
		return Release{}, errors.New("KBS challenge response is not strict JSON")
	}
	challengeDocument, ok := challengeValue.(map[string]any)
	if !ok || !contract.ExactKeys(challengeDocument, "schema", "challenge_base64", "challenge_sha256") || challengeDocument["schema"] != kbsChallengeSchema || !contract.ValidDigest(challengeDocument["challenge_sha256"]) {
		return Release{}, errors.New("KBS challenge response has an invalid exact schema")
	}
	challengeRaw, err := decodeBoundedBase64(challengeDocument["challenge_base64"], contract.MaxDocumentBytes)
	if err != nil || contract.Digest(challengeRaw) != challengeDocument["challenge_sha256"] {
		return Release{}, errors.New("KBS challenge body digest is mismatched")
	}
	if parsed, err := contract.ParseChallenge(challengeRaw, "admission"); err != nil || parsed.Expected["job_context_digest"] != request.Document["job_context_digest"] || parsed.Expected["attempt_id"] != request.Document["attempt_id"] {
		return Release{}, errors.New("KBS challenge is not for the requested job attempt")
	}
	evidence, err := attestor.CollectForEKM(requestContext, challengeRaw, ekm)
	if err != nil || !validEvidence(evidence) || evidence.TLSEKMSHA256 != contract.Digest(ekm) {
		return Release{}, errors.New("KBS-channel Confidential Space evidence failed")
	}
	evidenceValue, err := contract.StrictJSON(evidence.Canonical)
	if err != nil {
		return Release{}, errors.New("KBS-channel evidence is not strict JSON")
	}
	releaseBody, _ := contract.CanonicalJSON(map[string]any{
		"schema": kbsReleaseSubmitSchema, "request": request.Document, "evidence": evidenceValue,
	})
	releaseResponse, releaseConnection, err := kbsRequest(requestContext, httpClient, connection, client.Origin+"/v1/releases", releaseBody)
	if errors.Is(err, errKBSResponseUncertain) && releaseConnection == connection {
		releaseResponse, releaseConnection, err = kbsRequest(requestContext, httpClient, connection, client.Origin+"/v1/releases", releaseBody)
	}
	if err != nil || releaseConnection != connection {
		return Release{}, errors.New("KBS release did not remain on the EKM-bound TLS connection")
	}
	return parseKBSRelease(releaseResponse, evidence)
}

var errKBSResponseUncertain = errors.New("KBS response may have been committed")

func kbsRequest(ctx context.Context, client *http.Client, wanted net.Conn, endpoint string, body []byte) ([]byte, net.Conn, error) {
	var observed net.Conn
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { observed = info.Conn }}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if observed != nil {
			return nil, observed, errKBSResponseUncertain
		}
		return nil, nil, err
	}
	defer response.Body.Close()
	if wanted != nil && observed != wanted {
		return nil, nil, errors.New("KBS HTTP request changed TLS connections")
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil, nil, errors.New("KBS returned a non-success response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, contract.MaxDocumentBytes+1))
	if err != nil || len(raw) == 0 {
		return nil, observed, errKBSResponseUncertain
	}
	if len(raw) > contract.MaxDocumentBytes {
		return nil, nil, errors.New("KBS response is empty or oversized")
	}
	return raw, observed, nil
}

func parseKBSRelease(raw []byte, evidence AttestedEvidence) (Release, error) {
	value, err := contract.StrictJSON(raw)
	if err != nil {
		return Release{}, errors.New("KBS release response is not strict JSON")
	}
	document, ok := value.(map[string]any)
	if !ok || !contract.ExactKeys(document, "schema", "ack", "grant_artifact_base64", "encrypted_items", "output_key_base64") || document["schema"] != kbsResponseSchema {
		return Release{}, errors.New("KBS release response has an invalid exact schema")
	}
	ack, ok := document["ack"].(map[string]any)
	if !ok {
		return Release{}, errors.New("KBS release ack is invalid")
	}
	ackRaw, _ := contract.CanonicalJSON(ack)
	artifact, err := decodeBoundedBase64(document["grant_artifact_base64"], contract.MaxDocumentBytes)
	if err != nil {
		return Release{}, err
	}
	outputKey, err := decodeBoundedBase64(document["output_key_base64"], 32)
	if err != nil || len(outputKey) != 32 {
		return Release{}, errors.New("KBS output sealing key is invalid")
	}
	itemValues, ok := document["encrypted_items"].([]any)
	if !ok || len(itemValues) > 32 {
		return Release{}, errors.New("KBS encrypted item set is invalid")
	}
	items := make([]EncryptedItem, 0, len(itemValues))
	for _, rawItem := range itemValues {
		item, ok := rawItem.(map[string]any)
		if !ok || !contract.ExactKeys(item, "kind", "owner_digest", "sealed_reference", "sealed_record_sha256", "ciphertext_sha256", "plaintext_sha256", "ciphertext_bytes", "plaintext_bytes", "nonce_prefix_base64", "key_base64") || !contract.ValidDigest(item["owner_digest"]) || !contract.ValidDigest(item["sealed_record_sha256"]) || !contract.ValidDigest(item["ciphertext_sha256"]) || !contract.ValidDigest(item["plaintext_sha256"]) {
			return Release{}, errors.New("KBS encrypted item has an invalid exact schema")
		}
		nonce, err := decodeBoundedBase64(item["nonce_prefix_base64"], 8)
		if err != nil || len(nonce) != 8 {
			return Release{}, errors.New("KBS encrypted item nonce prefix is invalid")
		}
		key, err := decodeBoundedBase64(item["key_base64"], 32)
		if err != nil || len(key) != 32 {
			return Release{}, errors.New("KBS encrypted item key is invalid")
		}
		kind, kindOK := item["kind"].(string)
		reference, referenceOK := item["sealed_reference"].(string)
		ciphertextBytes, cipherBytesOK := positiveJSONInt64(item["ciphertext_bytes"])
		plaintextBytes, plainBytesOK := positiveJSONInt64(item["plaintext_bytes"])
		if !kindOK || !referenceOK || reference == "" || !cipherBytesOK || !plainBytesOK || ciphertextBytes > 256*1024*1024*1024 || plaintextBytes > 256*1024*1024*1024 {
			return Release{}, errors.New("KBS encrypted item identity is invalid")
		}
		items = append(items, EncryptedItem{Kind: kind, OwnerDigest: item["owner_digest"].(string), SealedReference: reference, SealedRecordSHA256: item["sealed_record_sha256"].(string), CiphertextSHA256: item["ciphertext_sha256"].(string), PlaintextSHA256: item["plaintext_sha256"].(string), CiphertextBytes: ciphertextBytes, PlaintextBytes: plaintextBytes, NoncePrefix: nonce, Key: key})
	}
	return Release{AckCanonical: ackRaw, ArtifactCanonical: artifact, Items: items, OutputKey: outputKey, Evidence: evidence}, nil
}

func positiveJSONInt64(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil && parsed > 0
}

func decodeBoundedBase64(value any, maximum int) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("KBS base64 field is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, errors.New("KBS base64 field is not canonical or bounded")
	}
	return decoded, nil
}
