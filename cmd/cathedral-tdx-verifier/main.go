// cathedral-tdx-verifier verifies one Intel TDX quote and emits Cathedral's
// strict, quote-bound JSON claims contract.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

const (
	maxQuoteBytes      = 1024 * 1024
	maxCollateralBytes = 4 * 1024 * 1024
	verificationBudget = 25 * time.Second
	requestBudget      = 8 * time.Second
	platformDomain     = "cathedral-tdx-platform-v1\x00"
	measurementDomain  = "cathedral-tdx-measurement-v1\x00"
	tdxTcbInfoPath     = "/tdx/certification/v4/tcb"
	tdxQeIdentityPath  = "/tdx/certification/v4/qe/identity"
)

var intelCollateralHosts = map[string]struct{}{
	"api.trustedservices.intel.com":          {},
	"certificates.trustedservices.intel.com": {},
}

type claims struct {
	ReportData               string   `json:"report_data"`
	Measurement              string   `json:"measurement"`
	TcbSvn                   string   `json:"tcb_svn"`
	TcbStatus                string   `json:"tcb_status"`
	AdvisoryIDs              []string `json:"advisory_ids"`
	DebugEnabled             bool     `json:"debug_enabled"`
	CollateralCurrent        bool     `json:"collateral_current"`
	StablePlatformID         string   `json:"stable_platform_id"`
	PlatformID               string   `json:"platform_id"`
	PlatformIdentityKind     string   `json:"platform_identity_kind"`
	PlatformIdentityVerified bool     `json:"platform_identity_verified"`
	ClaimsBoundToQuote       bool     `json:"claims_bound_to_quote"`
	TdxPckCertID             string   `json:"tdx_pck_cert_id"`
	TdxAttestationKeyID      string   `json:"tdx_attestation_key_id"`
	IntelVerified            bool     `json:"intel_verified"`
	ReportDataMatch          bool     `json:"report_data_match"`
}

type launchBody interface {
	GetTeeTcbSvn() []byte
	GetTdAttributes() []byte
	GetXfam() []byte
	GetMrTd() []byte
	GetMrConfigId() []byte
	GetMrOwner() []byte
	GetMrOwnerConfig() []byte
	GetRtmrs() [][]byte
	GetReportData() []byte
}

type intelHTTPSGetter struct {
	client      *http.Client
	mu          sync.Mutex
	tcbInfoBody []byte
}

func newIntelHTTPSGetter() *intelHTTPSGetter {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        2,
		IdleConnTimeout:        15 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  6 * time.Second,
		MaxResponseHeaderBytes: 32 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &intelHTTPSGetter{client: &http.Client{
		Transport:     transport,
		Timeout:       requestBudget,
		CheckRedirect: checkIntelCollateralRedirect,
	}}
}

func checkIntelCollateralRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return errors.New("collateral redirect has no source request")
	}
	if len(via) >= 2 {
		return errors.New("too many collateral redirects")
	}
	original := via[0].URL
	if req.URL.EscapedPath() != original.EscapedPath() {
		return errors.New("collateral redirect changed the requested endpoint")
	}
	originalQuery, err := collateralRedirectInvariantQuery(original)
	if err != nil {
		return err
	}
	redirectQuery, err := collateralRedirectInvariantQuery(req.URL)
	if err != nil {
		return err
	}
	if redirectQuery != originalQuery {
		return errors.New("collateral redirect changed the requested resource")
	}
	return prepareIntelCollateralURL(req.URL)
}

func collateralRedirectInvariantQuery(parsed *url.URL) (string, error) {
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", errors.New("collateral URL has an invalid query")
	}
	if parsed.Path == tdxTcbInfoPath || parsed.Path == tdxQeIdentityPath {
		query.Del("update")
	}
	return query.Encode(), nil
}

func validateIntelURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("collateral URL is not an authenticated HTTPS URL")
	}
	if parsed.Port() != "" {
		return errors.New("collateral URL uses a non-default port")
	}
	host := strings.ToLower(parsed.Hostname())
	if _, ok := intelCollateralHosts[host]; !ok {
		return errors.New("collateral URL host is not allowed")
	}
	return nil
}

func prepareIntelCollateralURL(parsed *url.URL) error {
	if err := validateIntelURL(parsed); err != nil {
		return err
	}
	if parsed.Path != tdxTcbInfoPath && parsed.Path != tdxQeIdentityPath {
		return nil
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return errors.New("collateral URL has an invalid query")
	}
	if query.Has("tcbEvaluationDataNumber") {
		return errors.New("version-pinned Intel collateral is not accepted")
	}
	// Launch admission evaluates Intel's "standard" channel for both TDX TCB
	// Info and TDX QE Identity. Standard is Intel's default production posture;
	// the "early" channel applies TCB recovery requirements before cloud fleets
	// can deploy them and would reject all currently available hosts. The
	// channel is still normalized here so callers cannot select a different
	// one, and version-pinned collateral remains rejected.
	query.Set("update", "standard")
	parsed.RawQuery = query.Encode()
	return nil
}

func (g *intelHTTPSGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), rawURL)
}

func (g *intelHTTPSGetter) GetContext(
	ctx context.Context, rawURL string,
) (map[string][]string, []byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, errors.New("invalid collateral URL")
	}
	if err := prepareIntelCollateralURL(parsed); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, nil, errors.New("could not construct collateral request")
	}
	req.Header.Set("Accept", "application/json, application/pkix-crl, application/octet-stream")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, errors.New("collateral request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, fmt.Errorf("collateral endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCollateralBytes+1))
	if err != nil {
		return nil, nil, errors.New("could not read collateral response")
	}
	if len(body) > maxCollateralBytes {
		return nil, nil, errors.New("collateral response exceeds size limit")
	}
	if parsed.Path == tdxTcbInfoPath {
		g.mu.Lock()
		g.tcbInfoBody = bytes.Clone(body)
		g.mu.Unlock()
	}
	return resp.Header.Clone(), body, nil
}

func (g *intelHTTPSGetter) tcbInfoSnapshot() (pcs.TdxTcbInfo, error) {
	g.mu.Lock()
	body := bytes.Clone(g.tcbInfoBody)
	g.mu.Unlock()
	if len(body) == 0 {
		return pcs.TdxTcbInfo{}, errors.New("verified TDX TCB collateral was not captured")
	}
	var snapshot pcs.TdxTcbInfo
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return pcs.TdxTcbInfo{}, errors.New("captured TDX TCB collateral is invalid")
	}
	return snapshot, nil
}

func productionVerifyOptions() *verify.Options {
	return &verify.Options{
		CheckRevocations:      true,
		GetCollateral:         true,
		Getter:                newIntelHTTPSGetter(),
		DisableTcbStatusCheck: false,
	}
}

func readQuote(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("quote path must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("quote path is not readable")
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("quote path must be a regular non-symlink file")
	}
	if before.Size() <= 0 || before.Size() > maxQuoteBytes {
		return nil, errors.New("quote size is outside the accepted range")
	}

	handle, err := openQuoteFile(path)
	if err != nil {
		return nil, errors.New("quote path is not readable")
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("quote file changed before it was opened")
	}
	body, err := io.ReadAll(io.LimitReader(handle, maxQuoteBytes+1))
	if err != nil {
		return nil, errors.New("quote file could not be read")
	}
	if len(body) == 0 || len(body) > maxQuoteBytes || int64(len(body)) != opened.Size() {
		return nil, errors.New("quote file changed while it was read")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() ||
		after.ModTime() != opened.ModTime() {
		return nil, errors.New("quote file changed while it was read")
	}
	return body, nil
}

func launchQuoteV4(parsed any) (*tdxpb.QuoteV4, launchBody, error) {
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported launch quote type %T", parsed)
	}
	if len(quote.GetExtraBytes()) != 0 {
		return nil, nil, errors.New("quote contains unsigned trailing bytes")
	}
	body := quote.GetTdQuoteBody()
	if body == nil {
		return nil, nil, errors.New("quote has no TD body")
	}
	return quote, body, nil
}

func validateLaunchQuote(parsed any) error {
	return validate.TdxQuote(parsed, &validate.Options{
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			EnableTdDebugCheck:      true,
			EnableTdMigratableCheck: true,
		},
	})
}

func verifyAndBuildClaims(
	ctx context.Context, raw, expectedReportData []byte, options *verify.Options,
) (*claims, error) {
	if options == nil || !options.CheckRevocations || !options.GetCollateral ||
		options.DisableTcbStatusCheck {
		return nil, errors.New("production TDX verification checks are not enabled")
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, errors.New("quote does not satisfy the Intel TDX ABI")
	}
	quote, body, err := launchQuoteV4(parsed)
	if err != nil {
		return nil, err
	}
	if err := verify.TdxQuoteContext(ctx, quote, options); err != nil {
		return nil, errors.New("Intel quote, collateral, revocation, or TCB verification failed")
	}
	if err := requireCurrentCollateralLevels(quote, options); err != nil {
		return nil, errors.New("Intel platform, TDX module, or QE is not fully current")
	}
	if err := validateLaunchQuote(quote); err != nil {
		return nil, errors.New("quote uses launch-disallowed TDX attributes")
	}
	return buildVerifiedClaims(quote, body, expectedReportData)
}

func requireCurrentCollateralLevels(quote *tdxpb.QuoteV4, options *verify.Options) error {
	getter, ok := options.Getter.(*intelHTTPSGetter)
	if !ok {
		return errors.New("production collateral recorder is not configured")
	}
	snapshot, err := getter.tcbInfoSnapshot()
	if err != nil {
		return err
	}
	platformLevel, err := matchingPlatformTcbLevel(quote, snapshot.TcbInfo)
	if err != nil {
		return err
	}
	moduleLevel, qeLevel, err := verify.SupportedTcbLevelsFromCollateral(quote, options)
	if err != nil {
		return err
	}
	return validateCurrentCollateralLevels(platformLevel, moduleLevel, qeLevel)
}

func matchingPlatformTcbLevel(quote *tdxpb.QuoteV4, tcbInfo pcs.TcbInfo) (pcs.TcbLevel, error) {
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil || chain.PCKCertificate == nil {
		return pcs.TcbLevel{}, errors.New("verified quote does not contain a PCK certificate")
	}
	extensions, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return pcs.TcbLevel{}, errors.New("verified PCK certificate lacks TCB identity")
	}
	if !strings.EqualFold(tcbInfo.Fmspc, extensions.FMSPC) {
		return pcs.TcbLevel{}, errors.New("TDX TCB collateral does not match the verified platform")
	}
	teeTcbSvn := quote.GetTdQuoteBody().GetTeeTcbSvn()
	if len(teeTcbSvn) != 16 || len(extensions.TCB.CPUSvnComponents) != 16 {
		return pcs.TcbLevel{}, errors.New("verified quote has malformed TCB components")
	}
	tdxStart := 0
	if teeTcbSvn[1] > 0 {
		tdxStart = 2
	}
	for _, level := range tcbInfo.TcbLevels {
		if componentSvnAtLeast(extensions.TCB.CPUSvnComponents, level.Tcb.SgxTcbcomponents, 0) &&
			extensions.TCB.PCESvn >= level.Tcb.Pcesvn &&
			componentSvnAtLeast(teeTcbSvn, level.Tcb.TdxTcbcomponents, tdxStart) {
			return level, nil
		}
	}
	return pcs.TcbLevel{}, errors.New("no matching TDX platform TCB level")
}

func componentSvnAtLeast(given []byte, required []pcs.TcbComponent, start int) bool {
	if len(given) != len(required) || start < 0 || start > len(given) {
		return false
	}
	for index := start; index < len(given); index++ {
		if given[index] < required[index].Svn {
			return false
		}
	}
	return true
}

func validateCurrentCollateralLevels(platformLevel, moduleLevel, qeLevel pcs.TcbLevel) error {
	for _, candidate := range []struct {
		name  string
		level pcs.TcbLevel
	}{
		{name: "TDX platform", level: platformLevel},
		{name: "TDX module", level: moduleLevel},
		{name: "TDX quoting enclave", level: qeLevel},
	} {
		if candidate.level.TcbStatus != pcs.TcbComponentStatusUpToDate {
			return fmt.Errorf("%s TCB status is %q", candidate.name, candidate.level.TcbStatus)
		}
		if len(candidate.level.AdvisoryIDs) != 0 {
			return fmt.Errorf("%s UpToDate level unexpectedly carries advisories", candidate.name)
		}
	}
	return nil
}

func buildVerifiedClaims(
	quote *tdxpb.QuoteV4, body launchBody, expectedReportData []byte,
) (*claims, error) {
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil || chain.PCKCertificate == nil {
		return nil, errors.New("verified quote does not contain a PCK certificate")
	}
	extensions, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, errors.New("verified PCK certificate lacks required platform identity")
	}
	stableID, err := stablePlatformID(extensions.PPID)
	if err != nil {
		return nil, err
	}
	signed := quote.GetSignedData()
	if signed == nil || len(signed.GetEcdsaAttestationKey()) != 64 {
		return nil, errors.New("verified quote has an invalid attestation key")
	}
	if len(body.GetReportData()) != 64 || len(body.GetTeeTcbSvn()) != 16 {
		return nil, errors.New("verified quote has invalid report data or TCB SVN")
	}
	if len(expectedReportData) != 64 || subtle.ConstantTimeCompare(
		body.GetReportData(), expectedReportData,
	) != 1 {
		return nil, errors.New("verified quote report data does not match the expected binding")
	}
	measurement, err := measurementID(body)
	if err != nil {
		return nil, err
	}
	pckDigest := sha256.Sum256(chain.PCKCertificate.Raw)
	akDigest := sha256.Sum256(signed.GetEcdsaAttestationKey())
	return &claims{
		ReportData:               hex.EncodeToString(body.GetReportData()),
		Measurement:              measurement,
		TcbSvn:                   hex.EncodeToString(body.GetTeeTcbSvn()),
		TcbStatus:                "UpToDate",
		AdvisoryIDs:              []string{},
		DebugEnabled:             false,
		CollateralCurrent:        true,
		StablePlatformID:         stableID,
		PlatformID:               stableID,
		PlatformIdentityKind:     "stable",
		PlatformIdentityVerified: true,
		ClaimsBoundToQuote:       true,
		TdxPckCertID:             "tdx-pck-cert-sha256:" + hex.EncodeToString(pckDigest[:]),
		TdxAttestationKeyID:      "tdx-ak-sha256:" + hex.EncodeToString(akDigest[:]),
		IntelVerified:            true,
		ReportDataMatch:          true,
	}, nil
}

func stablePlatformID(rawPPID string) (string, error) {
	if len(rawPPID) != 32 || rawPPID != strings.ToLower(rawPPID) {
		return "", errors.New("verified PCK certificate has a non-canonical PPID")
	}
	if _, err := hex.DecodeString(rawPPID); err != nil {
		return "", errors.New("verified PCK certificate has an invalid PPID")
	}
	digest := sha256.Sum256([]byte(platformDomain + rawPPID))
	return "tdx-platform-sha256:" + hex.EncodeToString(digest[:]), nil
}

func measurementID(body launchBody) (string, error) {
	fields := [][]byte{
		body.GetTdAttributes(),
		body.GetXfam(),
		body.GetMrTd(),
		body.GetMrConfigId(),
		body.GetMrOwner(),
		body.GetMrOwnerConfig(),
	}
	wantLengths := []int{8, 8, 48, 48, 48, 48}
	for index, field := range fields {
		if len(field) != wantLengths[index] {
			return "", errors.New("verified quote has an invalid measurement field")
		}
	}
	if len(body.GetRtmrs()) != 4 {
		return "", errors.New("verified quote has an invalid RTMR count")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(measurementDomain))
	for _, field := range fields {
		_, _ = hash.Write(field)
	}
	for _, rtmr := range body.GetRtmrs() {
		if len(rtmr) != 48 {
			return "", errors.New("verified quote has an invalid RTMR")
		}
		_, _ = hash.Write(rtmr)
	}
	return "tdx-measurement-sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func parseExpectedReportData(raw string) ([]byte, error) {
	if len(raw) != 128 || raw != strings.ToLower(raw) {
		return nil, errors.New("expected report data must be 64 lowercase-hex bytes")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 64 {
		return nil, errors.New("expected report data must be 64 lowercase-hex bytes")
	}
	return decoded, nil
}

func run(args []string, output io.Writer) error {
	if len(args) != 2 {
		return errors.New(
			"usage: cathedral-tdx-verifier /absolute/path/to/quote <expected-report-data-hex>",
		)
	}
	raw, err := readQuote(args[0])
	if err != nil {
		return err
	}
	expectedReportData, err := parseExpectedReportData(args[1])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), verificationBudget)
	defer cancel()
	result, err := verifyAndBuildClaims(ctx, raw, expectedReportData, productionVerifyOptions())
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func main() {
	// go-tdx-guest initializes its logger on stdout before main and its logger
	// cannot be reset. Keep a private duplicate for the final JSON and send the
	// process stdout descriptor to the null device before any verification.
	claimOutput, err := isolatedClaimOutput()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cathedral TDX verification failed: stdout isolation failed")
		os.Exit(1)
	}
	defer claimOutput.Close()
	if err := run(os.Args[1:], claimOutput); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cathedral TDX verification failed:", err)
		os.Exit(1)
	}
}
