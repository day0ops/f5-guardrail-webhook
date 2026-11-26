package f5client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/day0ops/f5-guardrail-webhook/internal/f5client"
)

func TestScan_SendsExpectedRequestShape(t *testing.T) {
	type wantBody struct {
		Input         string `json:"input"`
		Project       string `json:"project"`
		ScanDirection string `json:"scanDirection"`
		FlagOnly      bool   `json:"flagOnly"`
		Verbose       bool   `json:"verbose"`
	}
	want := wantBody{Input: "hello", Project: "demo-project", ScanDirection: "request", FlagOnly: false, Verbose: true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/backend/v1/scans" {
			t.Errorf("path = %s, want /backend/v1/scans", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}

		var body wantBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		} else if body != want {
			t.Errorf("request body = %+v, want %+v", body, want)
		}

		fmt.Fprint(w, `{"result":{"outcome":"clean"}}`)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	got, err := client.Scan(context.Background(), "hello", "request")
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got.Outcome != "clean" {
		t.Errorf("Outcome = %q, want %q", got.Outcome, "clean")
	}
}

func TestNew_TrimsTrailingSlashFromBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend/v1/scans" {
			t.Errorf("path = %s, want /backend/v1/scans (a trailing slash in baseURL must not double up)", r.URL.Path)
		}
		fmt.Fprint(w, `{"result":{"outcome":"clean"}}`)
	}))
	defer server.Close()

	client := f5client.New(server.URL+"/", "test-token", "demo-project", time.Second)
	if _, err := client.Scan(context.Background(), "hello", "request"); err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
}

func TestScan_ParsesOutcomeAndRedactedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"result":{"outcome":"blocked"},"redactedInput":"re-written text"}`)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	got, err := client.Scan(context.Background(), "hello", "request")
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got.Outcome != "blocked" {
		t.Errorf("Outcome = %q, want %q", got.Outcome, "blocked")
	}
	if got.RedactedInput != "re-written text" {
		t.Errorf("RedactedInput = %q, want %q", got.RedactedInput, "re-written text")
	}
}

func TestScan_BuildsReasonFromScannerResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"result":{"outcome":"blocked","scannerResults":[
			{"scannerVersionMeta":{"name":"pii-detector"}},
			{"scannerId":"regex-ssn"},
			{}
		]}}`)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	got, err := client.Scan(context.Background(), "hello", "request")
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	want := "pii-detector, regex-ssn, scanner"
	if got.Reason != want {
		t.Errorf("Reason = %q, want %q", got.Reason, want)
	}
}

func TestScan_ReasonFallsBackToDefaultWhenScannerResultsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"result":{"outcome":"blocked","scannerResults":[]}}`)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	got, err := client.Scan(context.Background(), "hello", "request")
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	want := "F5 AI Guardrails"
	if got.Reason != want {
		t.Errorf("Reason = %q, want %q", got.Reason, want)
	}
}

func TestScan_ReturnsErrorOnNon2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	_, err := client.Scan(context.Background(), "hello", "request")
	if err == nil {
		t.Fatal("Scan() error = nil, want non-nil for a 500 response")
	}
}

func TestScan_ReturnsErrorOnMalformedJSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", time.Second)
	_, err := client.Scan(context.Background(), "hello", "request")
	if err == nil {
		t.Fatal("Scan() error = nil, want non-nil for a malformed JSON body")
	}
}

func TestScan_ReturnsErrorWhenContextDeadlineExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := f5client.New(server.URL, "test-token", "demo-project", 10*time.Millisecond)

	// Backstop so this test can't hang if Scan ever stops honoring the client timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Scan(ctx, "hello", "request")
	if err == nil {
		t.Fatal("Scan() error = nil, want non-nil when the request exceeds the client timeout")
	}
}
