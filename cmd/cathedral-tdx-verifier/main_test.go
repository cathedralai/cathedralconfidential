package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tdx-guest/verify"
)

func fixtureTimeSet() *verify.TimeSet {
	now := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	return &verify.TimeSet{
		PckCertChain: now,
		TcbInfo:      now,
		QeIdentity:   now,
		PckCrl:       now,
		RootCaCrl:    now,
	}
}

func canonicalQuoteV4Fixture(t *testing.T) []byte {
	t.Helper()
	raw := bytes.Clone(testdata.RawQuote)
	const (
		signedDataSizeOffset = 0x278
		signedDataOffset     = 0x27c
	)
	if len(raw) < signedDataOffset {
		t.Fatal("official quote fixture is truncated")
	}
	end := signedDataOffset + int(binary.LittleEndian.Uint32(
		raw[signedDataSizeOffset:signedDataOffset],
	))
	if end > len(raw) {
		t.Fatal("official quote fixture declares truncated signed data")
	}
	return raw[:end]
}

func fixtureClaims(t *testing.T) *claims {
	t.Helper()
	parsed, err := abi.QuoteToProto(canonicalQuoteV4Fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	quote, body, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatal(err)
	}
	result, err := buildVerifiedClaims(quote, body, body.GetReportData())
	if err != nil {
		t.Fatalf("buildVerifiedClaims() error = %v", err)
	}
	return result
}

func TestOfficialQuoteFixtureProducesCanonicalClaimFields(t *testing.T) {
	got := fixtureClaims(t)
	wants := map[string]string{
		"stable platform": "tdx-platform-sha256:2241d1d4f0830bbf9c06bf338cae17d8e9db9c2bca38811b58d9888125f2d43a",
		"measurement":     "tdx-measurement-sha256:306d11c6a17f18fdad1fabd0147ab4c3c625cab9cf89d5f8146a5f6e0345171c",
		"tcb svn":         "03000400000000000000000000000000",
		"pck cert":        "tdx-pck-cert-sha256:0079287e7f9e69dd94329cefb689c789ba5041ba3cead48cf6792e650616364d",
		"attestation key": "tdx-ak-sha256:159c4e0999ee1afd8c0053b5c04d5843cbc02579a283187ec8cc31f8dd337e8f",
	}
	if got.StablePlatformID != wants["stable platform"] || got.PlatformID != wants["stable platform"] {
		t.Errorf("stable platform ID = %q, want %q", got.StablePlatformID, wants["stable platform"])
	}
	if got.Measurement != wants["measurement"] {
		t.Errorf("measurement = %q, want %q", got.Measurement, wants["measurement"])
	}
	if got.TcbSvn != wants["tcb svn"] {
		t.Errorf("TCB SVN = %q, want %q", got.TcbSvn, wants["tcb svn"])
	}
	if got.TdxPckCertID != wants["pck cert"] {
		t.Errorf("PCK cert ID = %q, want %q", got.TdxPckCertID, wants["pck cert"])
	}
	if got.TdxAttestationKeyID != wants["attestation key"] {
		t.Errorf("attestation key ID = %q, want %q", got.TdxAttestationKeyID, wants["attestation key"])
	}
	if !got.IntelVerified || !got.ReportDataMatch || !got.CollateralCurrent ||
		!got.PlatformIdentityVerified || !got.ClaimsBoundToQuote {
		t.Errorf("verified claims contain a false assurance flag: %+v", got)
	}
	if got.DebugEnabled || got.TcbStatus != "UpToDate" || got.PlatformIdentityKind != "stable" {
		t.Errorf("verified claims contain an unexpected launch state: %+v", got)
	}
	if got.AdvisoryIDs == nil || len(got.AdvisoryIDs) != 0 {
		t.Errorf("advisory IDs = %#v, want a non-nil empty list", got.AdvisoryIDs)
	}
}

func TestClaimsNeverExposeRawPlatformIdentity(t *testing.T) {
	got := fixtureClaims(t)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawID := range []string{
		"089ddfdb9c0359c82a3bc7719239574e",
		"8c314d17d205dfafcbecbb00fc87eff7",
	} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(rawID)) {
			t.Fatalf("claims leaked raw platform identifier %q", rawID)
		}
	}
}

func TestTamperedOfficialQuoteFailsCrypto(t *testing.T) {
	raw := bytes.Clone(testdata.RawQuote)
	raw[100] ^= 0x01
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return
	}
	err = verify.TdxQuoteContext(context.Background(), parsed, &verify.Options{
		CheckRevocations:      true,
		GetCollateral:         true,
		Getter:                tdxtesting.TestGetter,
		Now:                   fixtureTimeSet(),
		DisableTcbStatusCheck: true,
	})
	if err == nil {
		t.Fatal("tampered quote unexpectedly verified")
	}
}

func TestClaimsPathRejectsDisabledProductionChecks(t *testing.T) {
	expectedReportData := bytes.Repeat([]byte{0}, 64)
	for name, options := range map[string]*verify.Options{
		"nil options":           nil,
		"no revocation check":   {GetCollateral: true},
		"no collateral":         {CheckRevocations: true},
		"TCB checking disabled": {CheckRevocations: true, GetCollateral: true, DisableTcbStatusCheck: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyAndBuildClaims(
				context.Background(), testdata.RawQuote, expectedReportData, options,
			); err == nil {
				t.Fatal("claims path accepted disabled production checks")
			}
		})
	}
}

func TestCurrentCollateralLevelsRejectBadPlatformModuleOrQeStatus(t *testing.T) {
	current := pcs.TcbLevel{TcbStatus: pcs.TcbComponentStatusUpToDate, AdvisoryIDs: []string{}}
	if err := validateCurrentCollateralLevels(current, current, current); err != nil {
		t.Fatalf("current collateral rejected: %v", err)
	}
	for name, levels := range map[string][3]pcs.TcbLevel{
		"outdated TDX platform": {
			{TcbStatus: pcs.TcbComponentStatusOutOfDate}, current, current,
		},
		"outdated TDX module": {
			current, {TcbStatus: pcs.TcbComponentStatusOutOfDate}, current,
		},
		"revoked TDX module": {
			current, {TcbStatus: pcs.TcbComponentStatusRevoked}, current,
		},
		"outdated QE": {
			current, current, {TcbStatus: pcs.TcbComponentStatusOutOfDate},
		},
		"advisory on current platform": {
			{TcbStatus: pcs.TcbComponentStatusUpToDate, AdvisoryIDs: []string{"INTEL-SA-TEST"}}, current, current,
		},
		"advisory on current module": {
			current, {TcbStatus: pcs.TcbComponentStatusUpToDate, AdvisoryIDs: []string{"INTEL-SA-TEST"}}, current,
		},
		"advisory on current QE": {
			current, current, {TcbStatus: pcs.TcbComponentStatusUpToDate, AdvisoryIDs: []string{"INTEL-SA-TEST"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCurrentCollateralLevels(levels[0], levels[1], levels[2]); err == nil {
				t.Fatal("non-current collateral level unexpectedly accepted")
			}
		})
	}
}

func TestPlatformTcbMatcherUsesVerifiedQuoteAndCollateral(t *testing.T) {
	parsed, err := abi.QuoteToProto(canonicalQuoteV4Fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	quote, _, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	extensions, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	sgxComponents := make([]pcs.TcbComponent, len(extensions.TCB.CPUSvnComponents))
	for index, svn := range extensions.TCB.CPUSvnComponents {
		sgxComponents[index].Svn = svn
	}
	tdxComponents := make([]pcs.TcbComponent, len(quote.GetTdQuoteBody().GetTeeTcbSvn()))
	for index, svn := range quote.GetTdQuoteBody().GetTeeTcbSvn() {
		tdxComponents[index].Svn = svn
	}
	collateral := pcs.TcbInfo{
		Fmspc: extensions.FMSPC,
		TcbLevels: []pcs.TcbLevel{{
			Tcb: pcs.Tcb{
				SgxTcbcomponents: sgxComponents,
				Pcesvn:           extensions.TCB.PCESvn,
				TdxTcbcomponents: tdxComponents,
			},
			TcbStatus: pcs.TcbComponentStatusUpToDate,
		}},
	}
	level, err := matchingPlatformTcbLevel(quote, collateral)
	if err != nil {
		t.Fatalf("matchingPlatformTcbLevel() error = %v", err)
	}
	if level.TcbStatus != pcs.TcbComponentStatusUpToDate {
		t.Fatalf("platform TCB matcher returned status %q", level.TcbStatus)
	}
}

func TestProductionOptionsFailClosed(t *testing.T) {
	options := productionVerifyOptions()
	if !options.CheckRevocations || !options.GetCollateral || options.DisableTcbStatusCheck {
		t.Fatalf("production verification options are not fail closed: %+v", options)
	}
}

func TestLaunchValidationRejectsDebugAndMigration(t *testing.T) {
	for name, mutate := range map[string]func(*tdxpb.QuoteV4){
		"debug": func(quote *tdxpb.QuoteV4) {
			quote.TdQuoteBody.TdAttributes[0] |= 0x01
		},
		"migratable": func(quote *tdxpb.QuoteV4) {
			quote.TdQuoteBody.TdAttributes[3] |= 0x20
		},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := abi.QuoteToProto(bytes.Clone(testdata.RawQuote))
			if err != nil {
				t.Fatal(err)
			}
			quote := parsed.(*tdxpb.QuoteV4)
			mutate(quote)
			if err := validateLaunchQuote(quote); err == nil {
				t.Fatalf("launch validation accepted %s quote", name)
			}
		})
	}
}

func TestQuoteV5FailsClosedUntilMeasurementContractIsVersioned(t *testing.T) {
	parsed, err := abi.QuoteToProto(testdata.RawQuoteV5)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := launchQuoteV4(parsed); err == nil {
		t.Fatal("quote v5 unexpectedly entered the v4 launch path")
	}
}

func TestQuoteWithUnsignedTrailingBytesFailsClosed(t *testing.T) {
	parsed, err := abi.QuoteToProto(append(canonicalQuoteV4Fixture(t), 0x00))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := launchQuoteV4(parsed); err == nil {
		t.Fatal("quote with unsigned trailing bytes unexpectedly entered the launch path")
	}
}

func TestReportDataMustMatchExpectedBinding(t *testing.T) {
	parsed, err := abi.QuoteToProto(canonicalQuoteV4Fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	quote, body, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildVerifiedClaims(quote, body, body.GetReportData()); err != nil {
		t.Fatalf("exact expected report data rejected: %v", err)
	}
	wrong := bytes.Clone(body.GetReportData())
	wrong[0] ^= 0x01
	if _, err := buildVerifiedClaims(quote, body, wrong); err == nil {
		t.Fatal("mismatched expected report data unexpectedly accepted")
	}
}

func TestMeasurementMatchesPythonContractVector(t *testing.T) {
	body := &tdxpb.TDQuoteBody{
		TdAttributes:  bytes.Repeat([]byte("T"), 8),
		Xfam:          bytes.Repeat([]byte("X"), 8),
		MrTd:          bytes.Repeat([]byte("M"), 48),
		MrConfigId:    bytes.Repeat([]byte("C"), 48),
		MrOwner:       bytes.Repeat([]byte("O"), 48),
		MrOwnerConfig: bytes.Repeat([]byte("o"), 48),
		Rtmrs: [][]byte{
			bytes.Repeat([]byte("0"), 48),
			bytes.Repeat([]byte("1"), 48),
			bytes.Repeat([]byte("2"), 48),
			bytes.Repeat([]byte("3"), 48),
		},
	}
	got, err := measurementID(body)
	if err != nil {
		t.Fatal(err)
	}
	want := "tdx-measurement-sha256:b3cf84af07e6fb79dce23c46eef78eb627b39989814fcf1b6ea42fd93fea1585"
	if got != want {
		t.Errorf("measurementID() = %q, want Python contract vector %q", got, want)
	}
}

func TestStablePlatformIDRejectsNonCanonicalPPID(t *testing.T) {
	for _, raw := range []string{
		"",
		"089DDFDB9C0359C82A3BC7719239574E",
		"089ddfdb9c0359c82a3bc7719239574",
		"089ddfdb9c0359c82a3bc7719239574z",
	} {
		if _, err := stablePlatformID(raw); err == nil {
			t.Errorf("stablePlatformID(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestCollateralURLAllowlist(t *testing.T) {
	accepted, _ := url.Parse("https://api.trustedservices.intel.com/tdx/certification/v4/tcb")
	if err := validateIntelURL(accepted); err != nil {
		t.Fatalf("official Intel URL rejected: %v", err)
	}
	for _, raw := range []string{
		"http://api.trustedservices.intel.com/tdx/certification/v4/tcb",
		"https://api.trustedservices.intel.com:8443/tdx/certification/v4/tcb",
		"https://user@api.trustedservices.intel.com/tdx/certification/v4/tcb",
		"https://api.trustedservices.intel.com.attacker.example/tdx/certification/v4/tcb",
		"https://127.0.0.1/collateral",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateIntelURL(parsed); err == nil {
			t.Errorf("untrusted collateral URL accepted: %s", raw)
		}
	}
}

func TestCollateralURLForcesPublicDisclosureChannel(t *testing.T) {
	for _, raw := range []string{
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000",
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000&update=standard",
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareIntelCollateralURL(parsed); err != nil {
			t.Fatalf("prepareIntelCollateralURL(%q) error = %v", raw, err)
		}
		if got := parsed.Query().Get("update"); got != "early" {
			t.Fatalf("prepared collateral update = %q, want early: %s", got, parsed)
		}
	}

	pinned, _ := url.Parse("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000&tcbEvaluationDataNumber=12")
	if err := prepareIntelCollateralURL(pinned); err == nil {
		t.Fatal("version-pinned TCB collateral unexpectedly accepted")
	}

	crl, _ := url.Parse("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der")
	if err := prepareIntelCollateralURL(crl); err != nil {
		t.Fatalf("PCK CRL URL rejected: %v", err)
	}
	if crl.Query().Has("update") {
		t.Fatal("PCK CRL URL unexpectedly received an update channel")
	}

	source, err := http.NewRequest(
		http.MethodGet,
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000&update=early",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := http.NewRequest(
		http.MethodGet,
		"https://certificates.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000&update=standard",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIntelCollateralRedirect(redirect, []*http.Request{source}); err != nil {
		t.Fatalf("safe collateral redirect rejected: %v", err)
	}
	if got := redirect.URL.Query().Get("update"); got != "early" {
		t.Fatalf("redirect update = %q, want early", got)
	}

	for name, raw := range map[string]string{
		"version pin":    "https://certificates.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000&tcbEvaluationDataNumber=12",
		"endpoint class": "https://certificates.trustedservices.intel.com/tdx/certification/v4/qe/identity?fmspc=50806f000000",
		"platform":       "https://certificates.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=60806f000000",
	} {
		t.Run("redirect rejects "+name, func(t *testing.T) {
			target, err := http.NewRequest(http.MethodGet, raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkIntelCollateralRedirect(target, []*http.Request{source}); err == nil {
				t.Fatalf("unsafe collateral redirect accepted: %s", raw)
			}
		})
	}

	crlSource, err := http.NewRequest(
		http.MethodGet,
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	changedCRL, err := http.NewRequest(
		http.MethodGet,
		"https://certificates.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIntelCollateralRedirect(changedCRL, []*http.Request{crlSource}); err == nil {
		t.Fatal("PCK CRL redirect changed the requested certificate authority")
	}

	for name, urls := range map[string][2]string{
		"PCK CRL added update": {
			"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
			"https://certificates.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der&update=standard",
		},
		"PCK CRL removed update": {
			"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der&update=early",
			"https://certificates.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
		},
		"PCK CRL changed update": {
			"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der&update=early",
			"https://certificates.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der&update=standard",
		},
		"root CRL added update": {
			"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
			"https://api.trustedservices.intel.com/IntelSGXRootCA.crl?update=standard",
		},
		"root CRL removed update": {
			"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl?update=early",
			"https://api.trustedservices.intel.com/IntelSGXRootCA.crl",
		},
		"root CRL changed update": {
			"https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl?update=early",
			"https://api.trustedservices.intel.com/IntelSGXRootCA.crl?update=standard",
		},
	} {
		t.Run("redirect rejects "+name, func(t *testing.T) {
			source, err := http.NewRequest(http.MethodGet, urls[0], nil)
			if err != nil {
				t.Fatal(err)
			}
			target, err := http.NewRequest(http.MethodGet, urls[1], nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkIntelCollateralRedirect(target, []*http.Request{source}); err == nil {
				t.Fatalf("collateral redirect changed update selector: %s", urls[1])
			}
		})
	}
}

func TestReadQuoteRejectsRelativeSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "quote.bin")
	if err := os.WriteFile(valid, []byte("quote"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readQuote("quote.bin"); err == nil {
		t.Error("relative quote path unexpectedly accepted")
	}
	symlink := filepath.Join(directory, "quote-link.bin")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readQuote(symlink); err == nil {
		t.Error("symlink quote path unexpectedly accepted")
	}
	oversize := filepath.Join(directory, "oversize.bin")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte{0x41}, maxQuoteBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readQuote(oversize); err == nil {
		t.Error("oversized quote unexpectedly accepted")
	}
}

func TestRunRequiresAbsolutePathAndExpectedReportData(t *testing.T) {
	directory := t.TempDir()
	quotePath := filepath.Join(directory, "quote.bin")
	if err := os.WriteFile(quotePath, []byte("not-a-quote"), 0o600); err != nil {
		t.Fatal(err)
	}
	validExpected := strings.Repeat("00", 64)
	for _, args := range [][]string{
		nil,
		{quotePath},
		{quotePath, validExpected, "extra"},
		{"relative.quote", validExpected},
		{quotePath, "not-hex"},
		{quotePath, strings.ToUpper(validExpected[:126] + "aa")},
	} {
		if err := run(args, &strings.Builder{}); err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
	}
}

func TestStdoutIsolationKeepsVerifierLogsOutOfClaims(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("stdout descriptor isolation is production-Linux specific")
	}
	if os.Getenv("CATHEDRAL_STDOUT_HELPER") == "1" {
		claimOutput, err := isolatedClaimOutput()
		if err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("upstream verifier warning\n")
		if err := json.NewEncoder(claimOutput).Encode(map[string]bool{"ok": true}); err != nil {
			os.Exit(3)
		}
		if err := claimOutput.Close(); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestStdoutIsolationKeepsVerifierLogsOutOfClaims$")
	command.Env = append(os.Environ(), "CATHEDRAL_STDOUT_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("stdout isolation helper failed: %v; stderr=%q", err, stderr.String())
	}
	if got, want := stdout.String(), "{\"ok\":true}\n"; got != want {
		t.Fatalf("isolated stdout = %q, want only claims JSON %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stdout isolation helper wrote stderr: %q", stderr.String())
	}
}
