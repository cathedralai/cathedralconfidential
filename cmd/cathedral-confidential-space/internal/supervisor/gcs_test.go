package supervisor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

type fixedTokenSource struct{}

func (fixedTokenSource) Token(context.Context) (string, error) { return "test-token", nil }

type loseFirstWriteTransport struct {
	base http.RoundTripper
	lock sync.Mutex
	lost bool
}

func (transport *loseFirstWriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil || request.Method != http.MethodPost {
		return response, err
	}
	transport.lock.Lock()
	defer transport.lock.Unlock()
	if transport.lost {
		return response, nil
	}
	transport.lost = true
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, errors.New("simulated response loss after commit")
}

func TestGCSConditionalWritesRecoverOnlyExactCommittedBytes(t *testing.T) {
	var lock sync.Mutex
	var objectName string
	var objectValue []byte
	var generation uint64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		if request.Method == http.MethodPost {
			body, _ := io.ReadAll(request.Body)
			wanted := request.URL.Query().Get("ifGenerationMatch")
			if wanted == "0" && generation != 0 || wanted != "0" && wanted != strconv.FormatUint(generation, 10) {
				response.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			objectName = request.URL.Query().Get("name")
			objectValue = append([]byte(nil), body...)
			generation++
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"name":"` + objectName + `","generation":"` + strconv.FormatUint(generation, 10) + `"}`))
			return
		}
		if generation == 0 {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if request.URL.Query().Get("alt") == "media" {
			if wanted := request.URL.Query().Get("generation"); wanted != "" && wanted != strconv.FormatUint(generation, 10) {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = response.Write(objectValue)
			return
		}
		_, _ = response.Write([]byte(`{"name":"` + objectName + `","generation":"` + strconv.FormatUint(generation, 10) + `"}`))
	}))
	defer server.Close()

	transport := &loseFirstWriteTransport{base: http.DefaultTransport}
	store := &GCSClient{
		Bucket: "test-bucket", Prefix: "attempts/test", Origin: server.URL,
		Client: &http.Client{Transport: transport}, Tokens: fixedTokenSource{},
	}
	first := []byte(`{"state":"admission"}`)
	createdGeneration, err := store.PutCreateOnly(context.Background(), "admission.json", first, "application/json")
	if err != nil || createdGeneration != "1" {
		t.Fatalf("lost create response was not recovered: generation=%q err=%v", createdGeneration, err)
	}
	if replayGeneration, err := store.PutCreateOnly(context.Background(), "admission.json", first, "application/json"); err != nil || replayGeneration != "1" {
		t.Fatalf("exact create retry was not idempotent: generation=%q err=%v", replayGeneration, err)
	}
	if _, err := store.PutCreateOnly(context.Background(), "admission.json", []byte(`{"state":"substituted"}`), "application/json"); err == nil {
		t.Fatal("create-only retry accepted conflicting bytes")
	}

	transport.lock.Lock()
	transport.lost = false
	transport.lock.Unlock()
	second := []byte(`{"state":"running"}`)
	updatedGeneration, err := store.PutCAS(context.Background(), "admission.json", second, "1")
	if err != nil || updatedGeneration != "2" {
		t.Fatalf("lost CAS response was not recovered: generation=%q err=%v", updatedGeneration, err)
	}
	if _, err := store.PutCAS(context.Background(), "admission.json", []byte(`{"state":"stale"}`), "1"); err == nil {
		t.Fatal("stale CAS accepted conflicting bytes")
	}
}
