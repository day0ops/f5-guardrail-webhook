package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/day0ops/f5-guardrail-webhook/internal/guard"
	"github.com/day0ops/f5-guardrail-webhook/internal/server"
)

// scannerCall records one Scan invocation's text and direction, in call order,
// so tests can assert how many scans ran and what each one saw.
type scannerCall struct {
	text      string
	direction string
}

// fakeScanner is a guard.Scanner test double that records every call it
// receives, so tests can assert the server passed it the right inputs and
// made (or stopped making) the expected number of calls.
//
// Scan returns, in priority order: err on the failOnCall'th call (1-indexed,
// 0 disables this); otherwise the matching entry of results by call order;
// otherwise the fallback result/err.
type fakeScanner struct {
	result guard.ScanResult
	err    error

	results    []guard.ScanResult
	failOnCall int

	gotText      string
	gotDirection string
	calls        []scannerCall
}

func (f *fakeScanner) Scan(_ context.Context, text, direction string) (guard.ScanResult, error) {
	f.gotText = text
	f.gotDirection = direction
	f.calls = append(f.calls, scannerCall{text: text, direction: direction})

	callNum := len(f.calls)
	if f.failOnCall > 0 && callNum == f.failOnCall {
		return guard.ScanResult{}, f.err
	}
	if idx := callNum - 1; idx < len(f.results) {
		return f.results[idx], nil
	}
	return f.result, f.err
}

// newBatchServer builds a Server in SCAN_MODE=batch mode: today's original
// whole-blob-per-direction scanning, now opt-in.
func newBatchServer(scanner guard.Scanner) *server.Server {
	return server.New(scanner, true)
}

// newPerMessageServer builds a Server in the default per-message scanning mode.
func newPerMessageServer(scanner guard.Scanner) *server.Server {
	return server.New(scanner, false)
}

// captureLog redirects the standard logger's output to a buffer for the rest
// of the test, restoring it on cleanup, so a test can assert on the server's
// single decision log line without running processes in parallel.
//
// Not safe under t.Parallel(): it swaps the package-level log writer for the
// duration of the test, so parallel tests would race on it.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// decodeBody decodes an HTTP response body as a generic JSON object, failing
// the test on any decode error.
func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()

	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return decoded
}

// decodeAction decodes an HTTP response body and returns its "action" object.
func decodeAction(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()

	decoded := decodeBody(t, resp)
	action, ok := decoded["action"].(map[string]any)
	if !ok {
		t.Fatalf("response body has no object \"action\" key: %#v", decoded)
	}
	return action
}

func TestHealthz_ReturnsOk(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{}).Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	decoded := decodeBody(t, resp)
	if decoded["status"] != "ok" {
		t.Errorf("status field = %v, want %q", decoded["status"], "ok")
	}
}

func TestRequest_PassesThroughWhenScannerReturnsClean(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newBatchServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[{"role":"system","content":"be nice"},{"role":"user","content":"hi"}]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	want := map[string]any{"reason": "cleared"}
	if len(action) != len(want) || action["reason"] != want["reason"] {
		t.Errorf("action = %#v, want %#v", action, want)
	}
	if scanner.gotDirection != "request" {
		t.Errorf("scanner.gotDirection = %q, want %q", scanner.gotDirection, "request")
	}
	if want := "be nice\nhi"; scanner.gotText != want {
		t.Errorf("scanner.gotText = %q, want %q", scanner.gotText, want)
	}
}

func TestRequest_RejectsWhenScannerReturnsBlocked(t *testing.T) {
	result := guard.ScanResult{Outcome: "blocked", Reason: "toxicity"}
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: result}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[{"role":"user","content":"hi"}]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 403 {
		t.Errorf("action.status_code = %v, want 403", action["status_code"])
	}
	body, _ := action["body"].(string)
	if !strings.Contains(body, "toxicity") {
		t.Errorf("action.body = %q, want it to contain %q", body, "toxicity")
	}
}

func TestRequest_RejectsWithStatus503WhenScanFails(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{err: errors.New("boom")}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[{"role":"user","content":"hi"}]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 503 {
		t.Errorf("action.status_code = %v, want 503", action["status_code"])
	}
	reason, _ := action["reason"].(string)
	if !strings.Contains(reason, "F5 AI Guardrails request scan failed") {
		t.Errorf("action.reason = %q, want it to contain %q", reason, "F5 AI Guardrails request scan failed")
	}
}

func TestRequest_MasksWithRedactedBodyAtHTTPLevel(t *testing.T) {
	result := guard.ScanResult{Outcome: "clean", RedactedInput: "my ssn is [REDACTED]"}
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: result}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[{"role":"user","content":"my ssn is 123-45-6789"}]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
	if got := maskedRequestContent(t, action); got != "my ssn is [REDACTED]" {
		t.Errorf("masked content = %q, want %q", got, "my ssn is [REDACTED]")
	}
}

func TestResponse_MasksWhenScannerReturnsBlocked(t *testing.T) {
	result := guard.ScanResult{Outcome: "blocked"}
	scanner := &fakeScanner{result: result}
	ts := httptest.NewServer(newBatchServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[{"message":{"content":"secret"}},{"message":{"content":"stuff"}}]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
	if got := maskedContent(t, action); got != "" {
		t.Errorf("masked content = %q, want empty string", got)
	}
	if scanner.gotDirection != "response" {
		t.Errorf("scanner.gotDirection = %q, want %q", scanner.gotDirection, "response")
	}
	if want := "secret\nstuff"; scanner.gotText != want {
		t.Errorf("scanner.gotText = %q, want %q", scanner.gotText, want)
	}
}

func TestResponse_MasksWhenScanFails_DoesNotReturnRaw5xx(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{err: errors.New("boom")}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[{"message":{"content":"secret"}}]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d (not a raw 5xx)", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if got := maskedContent(t, action); got != "" {
		t.Errorf("masked content = %q, want empty string", got)
	}
	reason, _ := action["reason"].(string)
	if !strings.Contains(reason, "F5 AI Guardrails response scan failed") {
		t.Errorf("action.reason = %q, want it to contain %q", reason, "F5 AI Guardrails response scan failed")
	}
}

func TestRequest_PassesOnMissingMessagesField(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: guard.ScanResult{Outcome: "clean"}}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json", strings.NewReader(`{"body":{}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	want := map[string]any{"reason": "cleared"}
	if len(action) != len(want) || action["reason"] != want["reason"] {
		t.Errorf("action = %#v, want %#v", action, want)
	}
}

func TestRequest_RejectsWithStatus400OnMalformedJSON(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: guard.ScanResult{Outcome: "clean"}}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 400 {
		t.Errorf("action.status_code = %v, want 400", action["status_code"])
	}
}

func TestResponse_MasksOnMalformedJSON_NoStatusCode(t *testing.T) {
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: guard.ScanResult{Outcome: "clean"}}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
}

func TestRequest_PerMessage_RedactsOnlyTheMessageThatNeedsIt(t *testing.T) {
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"}, // gate (whole conversation)
			{Outcome: "clean"}, // system message
			{Outcome: "clean", RedactedInput: "my ssn is [REDACTED]"}, // user message
			{Outcome: "clean"}, // assistant message
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"my ssn is 123-45-6789"},`+
			`{"role":"assistant","content":"ok noted"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}

	contents := requestMessageContents(t, action)
	want := []string{"be nice", "my ssn is [REDACTED]", "ok noted"}
	if !slices.Equal(contents, want) {
		t.Errorf("message contents = %#v, want %#v", contents, want)
	}
	if len(scanner.calls) != 4 {
		t.Errorf("scanner.calls = %d, want 4 (one gate scan plus one per message)", len(scanner.calls))
	}
}

func TestRequest_PerMessage_BlockedMessageShortCircuitsRemainingScans(t *testing.T) {
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"},                       // gate (whole conversation)
			{Outcome: "clean"},                       // system message
			{Outcome: "blocked", Reason: "toxicity"}, // user message
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"say something toxic"},`+
			`{"role":"user","content":"should never be scanned"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 403 {
		t.Errorf("action.status_code = %v, want 403", action["status_code"])
	}
	body, _ := action["body"].(string)
	if !strings.Contains(body, "toxicity") {
		t.Errorf("action.body = %q, want it to contain %q", body, "toxicity")
	}

	if len(scanner.calls) != 3 {
		t.Fatalf("scanner.calls = %d, want 3 (gate, then scanning must stop at the blocking message)", len(scanner.calls))
	}
	if scanner.calls[2].text != "say something toxic" {
		t.Errorf("third scan call text = %q, want %q", scanner.calls[2].text, "say something toxic")
	}
}

// TestResponse_PerMessage_MasksOnlyTheChoiceThatNeedsIt covers three choices
// where the middle one is blocked and the other two are clean, with the clean
// third choice scanned after the blocked one. This exercises the
// severity-tracking combiner in decideResponsePerMessage: the final reason
// and logged outcome must reflect the most severe thing seen across all
// choices (blocked), not whichever choice was scanned last (which here is
// clean). A naive last-write-wins combiner would report reason "Redacted by
// F5 AI Guardrails" and outcome="clean" instead, so these assertions fail
// against that regression.
func TestResponse_PerMessage_MasksOnlyTheChoiceThatNeedsIt(t *testing.T) {
	buf := captureLog(t)
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"},                       // gate (whole conversation)
			{Outcome: "clean"},                       // first choice
			{Outcome: "blocked", Reason: "toxicity"}, // second choice
			{Outcome: "clean"},                       // third choice, scanned after the block
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[`+
			`{"message":{"content":"fine answer"}},`+
			`{"message":{"content":"toxic answer"}},`+
			`{"message":{"content":"another fine answer"}}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
	contents := responseChoiceContents(t, action)
	want := []string{"fine answer", "", "another fine answer"}
	if !slices.Equal(contents, want) {
		t.Errorf("choice contents = %#v, want %#v", contents, want)
	}
	if len(scanner.calls) != 4 {
		t.Errorf("scanner.calls = %d, want 4 (one gate scan plus one per choice, no short-circuit on response path)", len(scanner.calls))
	}

	reason, _ := action["reason"].(string)
	if want := "Blocked by F5 AI Guardrails: toxicity"; reason != want {
		t.Errorf("action.reason = %q, want %q (the most severe outcome's reason, not the later clean choice's)", reason, want)
	}
	if !strings.Contains(buf.String(), `outcome="blocked"`) {
		t.Errorf("log output = %q, want it to report outcome=\"blocked\" (the most severe outcome seen), not the later clean choice's outcome", buf.String())
	}
}

// TestRequest_PerMessage_ScanFailurePartwayRejectsWithStatus503 also covers
// the masked count on a reject-path log line: the first message is masked
// before the second message's scan fails, and the reject must still log
// masked=0, since a reject carries no masked content regardless of what an
// earlier message in the same request needed.
func TestRequest_PerMessage_ScanFailurePartwayRejectsWithStatus503(t *testing.T) {
	buf := captureLog(t)
	scanner := &fakeScanner{
		// gate, then first message (masked), then second message fails.
		results:    []guard.ScanResult{{Outcome: "clean"}, {Outcome: "clean", RedactedInput: "be nice REDACTED"}},
		failOnCall: 3, // second message's scan fails
		err:        errors.New("boom"),
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"hi"},`+
			`{"role":"user","content":"should never be scanned"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 503 {
		t.Errorf("action.status_code = %v, want 503", action["status_code"])
	}
	reason, _ := action["reason"].(string)
	if !strings.Contains(reason, "F5 AI Guardrails request scan failed") {
		t.Errorf("action.reason = %q, want it to contain %q", reason, "F5 AI Guardrails request scan failed")
	}
	if len(scanner.calls) != 3 {
		t.Errorf("scanner.calls = %d, want 3 (gate, first message, then scanning must stop at the failing call)", len(scanner.calls))
	}
	if !strings.Contains(buf.String(), "masked=0") {
		t.Errorf("log output = %q, want masked=0 (this rejects, so nothing was masked, even though the first message needed one)", buf.String())
	}
}

// TestResponse_PerMessage_ScanFailurePartwayMasksAllChoices also covers the
// masked count on this failure path: the first choice is masked before the
// second choice's scan fails, and the log must still report masked=3
// (len(body.Choices)), since maskAction masks every choice in body, not just
// the one already masked before the failure.
func TestResponse_PerMessage_ScanFailurePartwayMasksAllChoices(t *testing.T) {
	buf := captureLog(t)
	scanner := &fakeScanner{
		// gate, then first choice (masked), then second choice fails.
		results:    []guard.ScanResult{{Outcome: "clean"}, {Outcome: "clean", RedactedInput: "first choice redacted"}},
		failOnCall: 3, // second choice's scan fails
		err:        errors.New("boom"),
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[`+
			`{"message":{"content":"fine answer"}},`+
			`{"message":{"content":"will fail to scan"}},`+
			`{"message":{"content":"never reached"}}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
	contents := responseChoiceContents(t, action)
	want := []string{"", "", ""}
	if !slices.Equal(contents, want) {
		t.Errorf("choice contents = %#v, want all empty: %#v", contents, want)
	}
	reason, _ := action["reason"].(string)
	if !strings.Contains(reason, "F5 AI Guardrails response scan failed") {
		t.Errorf("action.reason = %q, want it to contain %q", reason, "F5 AI Guardrails response scan failed")
	}
	// The real point of this test: prove scanning actually stopped at the
	// failing call instead of continuing through the remaining choices. If
	// scanning had kept going, the third choice would still have been
	// "scanned" and we'd see 4 calls, not 3.
	if len(scanner.calls) != 3 {
		t.Errorf("scanner.calls = %d, want 3 (gate, first choice, then scanning must stop at the failing call)", len(scanner.calls))
	}
	if !strings.Contains(buf.String(), "masked=3") {
		t.Errorf("log output = %q, want masked=3 (every choice in body is masked on this failure path)", buf.String())
	}
}

func TestRequest_PerMessage_EmptyMessagesPassesWithZeroScanCalls(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json", strings.NewReader(`{"body":{"messages":[]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	want := map[string]any{"reason": "cleared"}
	if len(action) != len(want) || action["reason"] != want["reason"] {
		t.Errorf("action = %#v, want %#v", action, want)
	}
	if len(scanner.calls) != 0 {
		t.Errorf("scanner.calls = %d, want 0", len(scanner.calls))
	}
}

func TestResponse_PerMessage_EmptyChoicesPassesWithZeroScanCalls(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json", strings.NewReader(`{"body":{"choices":[]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	want := map[string]any{"reason": "cleared"}
	if len(action) != len(want) || action["reason"] != want["reason"] {
		t.Errorf("action = %#v, want %#v", action, want)
	}
	if len(scanner.calls) != 0 {
		t.Errorf("scanner.calls = %d, want 0", len(scanner.calls))
	}
}

// TestRequest_BatchMode_OverwritesWrongMessageAcrossMultiTurn documents
// SCAN_MODE=batch's known limitation: a mask always overwrites the last user
// message, not whichever message the scan actually flagged, so it is only
// safe for single-turn prompts.
func TestRequest_BatchMode_OverwritesWrongMessageAcrossMultiTurn(t *testing.T) {
	result := guard.ScanResult{Outcome: "clean", RedactedInput: "scrubbed whole conversation"}
	ts := httptest.NewServer(newBatchServer(&fakeScanner{result: result}).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"my ssn is 123-45-6789"},`+
			`{"role":"assistant","content":"ok noted"},`+
			`{"role":"user","content":"thanks"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	contents := requestMessageContents(t, action)
	want := []string{"be nice", "my ssn is 123-45-6789", "ok noted", "scrubbed whole conversation"}
	if !slices.Equal(contents, want) {
		t.Errorf("message contents = %#v, want %#v", contents, want)
	}
}

func TestRequest_Gated_TwoMessagesEachGetOwnRedaction(t *testing.T) {
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"}, // gate (whole conversation)
			{Outcome: "clean"}, // system message
			{Outcome: "clean", RedactedInput: "my ssn is [REDACTED]"}, // first user message
			{Outcome: "clean"}, // assistant message
			{Outcome: "clean", RedactedInput: "my email is [REDACTED]"}, // second user message
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"my ssn is 123-45-6789"},`+
			`{"role":"assistant","content":"ok noted"},`+
			`{"role":"user","content":"my email is a@b.com"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}

	contents := requestMessageContents(t, action)
	want := []string{"be nice", "my ssn is [REDACTED]", "ok noted", "my email is [REDACTED]"}
	if !slices.Equal(contents, want) {
		t.Errorf("message contents = %#v, want %#v (each redacted message must get its own distinct content, not the last mask applied to both)", contents, want)
	}
	if len(scanner.calls) != 5 {
		t.Errorf("scanner.calls = %d, want 5 (one gate scan plus one per message)", len(scanner.calls))
	}
}

func TestRequest_Gated_AllCleanMultiMessagePasses(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"hi"},`+
			`{"role":"assistant","content":"hello"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	want := map[string]any{"reason": "cleared"}
	if len(action) != len(want) || action["reason"] != want["reason"] {
		t.Errorf("action = %#v, want %#v", action, want)
	}
	if len(scanner.calls) != 4 {
		t.Errorf("scanner.calls = %d, want 4 (one gate scan plus one per message)", len(scanner.calls))
	}
}

func TestResponse_PerMessage_RedactsOnlyTheChoiceThatNeedsIt(t *testing.T) {
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"}, // gate (whole conversation)
			{Outcome: "clean"}, // first choice
			{Outcome: "clean", RedactedInput: "second choice redacted"}, // second choice
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[`+
			`{"message":{"content":"fine answer"}},`+
			`{"message":{"content":"my ssn is 123-45-6789"}}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v", action)
	}
	contents := responseChoiceContents(t, action)
	want := []string{"fine answer", "second choice redacted"}
	if !slices.Equal(contents, want) {
		t.Errorf("choice contents = %#v, want %#v", contents, want)
	}
	if len(scanner.calls) != 3 {
		t.Errorf("scanner.calls = %d, want 3 (one gate scan plus one per choice)", len(scanner.calls))
	}
}

// TestRequest_Gated_EarlierMaskThenLaterBlockRejects covers an earlier
// message that needed redaction followed by a later message that gets
// blocked. This does NOT exercise the response-side-style severity-tracking
// combiner: the request-side per-message loop rejects immediately via its
// existing early return the moment it hits a blocked message, so there is no
// "combine outcomes across several completed scans" step here, and
// pre-severity-fix code would reject here too. What this test actually
// proves is narrower: a block occurring after an earlier mask still wins and
// short-circuits further scanning on /request, and the reject-path log line
// reports masked=0 (nothing was masked, since the response is a reject, even
// though an earlier message in the same request was masked before the
// block).
func TestRequest_Gated_EarlierMaskThenLaterBlockRejects(t *testing.T) {
	buf := captureLog(t)
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean"}, // gate (whole conversation)
			{Outcome: "clean"}, // system message
			{Outcome: "clean", RedactedInput: "my ssn is [REDACTED]"}, // first user message (masked)
			{Outcome: "blocked", Reason: "toxicity"},                  // second user message (blocked)
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"my ssn is 123-45-6789"},`+
			`{"role":"user","content":"say something toxic"},`+
			`{"role":"user","content":"should never be scanned"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 403 {
		t.Errorf("action.status_code = %v, want 403 (reject must win over an earlier mask)", action["status_code"])
	}
	body, _ := action["body"].(string)
	if !strings.Contains(body, "toxicity") {
		t.Errorf("action.body = %q, want it to contain %q", body, "toxicity")
	}
	if len(scanner.calls) != 4 {
		t.Fatalf("scanner.calls = %d, want 4 (gate, system, masked message, then stop at the blocking message)", len(scanner.calls))
	}
	// The 4th (and last) call must be the blocking message itself, proving
	// the loop stopped there instead of scanning on to "should never be
	// scanned" - which is what it would do if the gate call were missing and
	// the result array happened to line up by coincidence.
	if want := "say something toxic"; scanner.calls[3].text != want {
		t.Errorf("4th scan call text = %q, want %q", scanner.calls[3].text, want)
	}
	if !strings.Contains(buf.String(), `outcome="blocked"`) {
		t.Errorf("log output = %q, want it to report outcome=\"blocked\" (the most severe outcome seen), not \"masked\" or the earlier message's \"clean\"", buf.String())
	}
	if !strings.Contains(buf.String(), "masked=0") {
		t.Errorf("log output = %q, want masked=0 (this rejects, so nothing was masked, even though an earlier message in the request was)", buf.String())
	}
}

// contextScanner is a guard.Scanner test double whose verdict depends on the
// exact text it is asked to scan, rather than on call order like fakeScanner.
// It exists to prove a block decision required the full joined conversation
// (the cross-turn attack this feature targets): individual messages here are
// each innocuous on their own, but the fn can recognize the full blob.
type contextScanner struct {
	fn    func(text string) guard.ScanResult
	calls []scannerCall
}

func (s *contextScanner) Scan(_ context.Context, text, direction string) (guard.ScanResult, error) {
	s.calls = append(s.calls, scannerCall{text: text, direction: direction})
	return s.fn(text), nil
}

// TestRequest_Gated_BlockedAtGateRejectsWithoutPerMessageCalls covers a
// conversation split across turns, with an innocuous setup message and a
// payload message that is only recognizable as an attack once joined with
// that context - something neither message would trip on its own. The gate
// scan (over the full joined blob) must be what catches it, must reject, and
// critically only that one call may have happened - zero per-message calls,
// since the gate already decided to block.
func TestRequest_Gated_BlockedAtGateRejectsWithoutPerMessageCalls(t *testing.T) {
	const setup = "innocuous setup"
	const payload = "now the payload"
	fullConversation := setup + "\n" + payload

	scanner := &contextScanner{fn: func(text string) guard.ScanResult {
		if text == fullConversation {
			return guard.ScanResult{Outcome: "blocked", Reason: "cross-turn attack"}
		}
		return guard.ScanResult{Outcome: "clean"}
	}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"user","content":"`+setup+`"},`+
			`{"role":"user","content":"`+payload+`"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if statusCode, _ := action["status_code"].(float64); statusCode != 403 {
		t.Errorf("action.status_code = %v, want 403", action["status_code"])
	}
	body, _ := action["body"].(string)
	if !strings.Contains(body, "cross-turn attack") {
		t.Errorf("action.body = %q, want it to contain %q", body, "cross-turn attack")
	}
	if len(scanner.calls) != 1 {
		t.Fatalf("scanner.calls = %d, want 1 (only the gate scan, zero per-message calls)", len(scanner.calls))
	}
	if scanner.calls[0].text != fullConversation {
		t.Errorf("the one scan call's text = %q, want the full joined conversation %q", scanner.calls[0].text, fullConversation)
	}
}

// TestRequest_Gated_PassesGateThenPerMessageRedactsIndependently covers a
// multi-message conversation that passes the gate (even though the gate scan
// itself carried a RedactedInput) and then needs per-message redaction: the
// gate's own redaction must never be applied, only the per-message scan's.
func TestRequest_Gated_PassesGateThenPerMessageRedactsIndependently(t *testing.T) {
	scanner := &fakeScanner{
		results: []guard.ScanResult{
			{Outcome: "clean", RedactedInput: "GATE REDACTION SHOULD NOT APPEAR"}, // gate
			{Outcome: "clean"}, // system message
			{Outcome: "clean", RedactedInput: "ssn redacted by per-message scan"}, // user message
		},
	}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[`+
			`{"role":"system","content":"be nice"},`+
			`{"role":"user","content":"my ssn is 123-45-6789"}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	contents := requestMessageContents(t, action)
	want := []string{"be nice", "ssn redacted by per-message scan"}
	if !slices.Equal(contents, want) {
		t.Errorf("message contents = %#v, want %#v (the gate's own redaction must not be applied)", contents, want)
	}
	if len(scanner.calls) != 3 {
		t.Errorf("scanner.calls = %d, want 3 (gate plus one per message)", len(scanner.calls))
	}
}

func TestRequest_SingleMessage_SkipsGate(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/request", "application/json",
		strings.NewReader(`{"body":{"messages":[{"role":"user","content":"hi"}]}}`))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if len(scanner.calls) != 1 {
		t.Errorf("scanner.calls = %d, want 1 (a single message never triggers the gate)", len(scanner.calls))
	}
}

// TestResponse_Gated_BlockedAtGateMasksWithoutPerMessageCalls mirrors
// TestRequest_Gated_BlockedAtGateRejectsWithoutPerMessageCalls for the
// response direction: a gate block masks the whole response to empty
// (matching old batch mode's mask-on-block behavior) rather than rejecting,
// and only the one gate call may have happened.
func TestResponse_Gated_BlockedAtGateMasksWithoutPerMessageCalls(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "blocked", Reason: "cross-turn leak"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[`+
			`{"message":{"content":"setup"}},`+
			`{"message":{"content":"leaked secret"}}`+
			`]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	action := decodeAction(t, resp)
	if _, hasStatusCode := action["status_code"]; hasStatusCode {
		t.Errorf("action has unexpected status_code key: %#v (response never rejects)", action)
	}
	contents := responseChoiceContents(t, action)
	want := []string{"", ""}
	if !slices.Equal(contents, want) {
		t.Errorf("choice contents = %#v, want all empty: %#v", contents, want)
	}
	reason, _ := action["reason"].(string)
	if !strings.Contains(reason, "Blocked by F5 AI Guardrails: cross-turn leak") {
		t.Errorf("action.reason = %q, want it to contain %q", reason, "Blocked by F5 AI Guardrails: cross-turn leak")
	}
	if len(scanner.calls) != 1 {
		t.Errorf("scanner.calls = %d, want 1 (only the gate scan, zero per-choice calls)", len(scanner.calls))
	}
	wantBody := guard.ChatResponseBody{Choices: []guard.ChatChoice{
		{Message: guard.ChatMessage{Content: "setup"}},
		{Message: guard.ChatMessage{Content: "leaked secret"}},
	}}
	if want := guard.ResponseText(wantBody); scanner.calls[0].text != want {
		t.Errorf("the one scan call's text = %q, want the full joined conversation %q", scanner.calls[0].text, want)
	}
}

func TestResponse_SingleChoice_SkipsGate(t *testing.T) {
	scanner := &fakeScanner{result: guard.ScanResult{Outcome: "clean"}}
	ts := httptest.NewServer(newPerMessageServer(scanner).Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/response", "application/json",
		strings.NewReader(`{"body":{"choices":[{"message":{"content":"fine answer"}}]}}`))
	if err != nil {
		t.Fatalf("POST /response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if len(scanner.calls) != 1 {
		t.Errorf("scanner.calls = %d, want 1 (a single choice never triggers the gate)", len(scanner.calls))
	}
}

// requestMessageContents extracts every message's content, in order, from
// action.body.messages, failing the test if the shape doesn't match.
func requestMessageContents(t *testing.T, action map[string]any) []string {
	t.Helper()

	body, ok := action["body"].(map[string]any)
	if !ok {
		t.Fatalf("action.body is not an object: %#v", action["body"])
	}
	messages, ok := body["messages"].([]any)
	if !ok {
		t.Fatalf("action.body.messages is not an array: %#v", body["messages"])
	}
	contents := make([]string, len(messages))
	for i, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok {
			t.Fatalf("action.body.messages[%d] is not an object: %#v", i, m)
		}
		contents[i], _ = msg["content"].(string)
	}
	return contents
}

// responseChoiceContents extracts every choice's message content, in order,
// from action.body.choices, failing the test if the shape doesn't match.
func responseChoiceContents(t *testing.T, action map[string]any) []string {
	t.Helper()

	body, ok := action["body"].(map[string]any)
	if !ok {
		t.Fatalf("action.body is not an object: %#v", action["body"])
	}
	choices, ok := body["choices"].([]any)
	if !ok {
		t.Fatalf("action.body.choices is not an array: %#v", body["choices"])
	}
	contents := make([]string, len(choices))
	for i, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("action.body.choices[%d] is not an object: %#v", i, c)
		}
		message, ok := choice["message"].(map[string]any)
		if !ok {
			t.Fatalf("action.body.choices[%d].message is not an object: %#v", i, choice["message"])
		}
		contents[i], _ = message["content"].(string)
	}
	return contents
}

// maskedContent extracts action.body.choices[0].message.content from a
// decoded response action, failing the test if the shape doesn't match.
func maskedContent(t *testing.T, action map[string]any) string {
	t.Helper()

	body, ok := action["body"].(map[string]any)
	if !ok {
		t.Fatalf("action.body is not an object: %#v", action["body"])
	}
	choices, ok := body["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("action.body.choices is not a non-empty array: %#v", body["choices"])
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("action.body.choices[0] is not an object: %#v", choices[0])
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		t.Fatalf("action.body.choices[0].message is not an object: %#v", choice["message"])
	}
	content, _ := message["content"].(string)
	return content
}

// maskedRequestContent extracts action.body.messages[0].content from a
// decoded request action, failing the test if the shape doesn't match.
func maskedRequestContent(t *testing.T, action map[string]any) string {
	t.Helper()

	body, ok := action["body"].(map[string]any)
	if !ok {
		t.Fatalf("action.body is not an object: %#v", action["body"])
	}
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatalf("action.body.messages is not a non-empty array: %#v", body["messages"])
	}
	message, ok := messages[0].(map[string]any)
	if !ok {
		t.Fatalf("action.body.messages[0] is not an object: %#v", messages[0])
	}
	content, _ := message["content"].(string)
	return content
}
