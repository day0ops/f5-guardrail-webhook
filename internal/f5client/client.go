// Package f5client calls F5 AI Guardrails' hosted Scan API over HTTP.
package f5client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/day0ops/f5-guardrail-webhook/internal/guard"
)

// scanPath is the Scan API endpoint, relative to a Client's baseURL.
const scanPath = "/backend/v1/scans"

// defaultReason is used when a scan response has no scanner results to name.
const defaultReason = "F5 AI Guardrails"

// maxLoggedBodyBytes caps how much of an error response body gets logged.
const maxLoggedBodyBytes = 500

// Client calls F5 AI Guardrails' hosted Scan API to classify and redact chat text.
// It implements guard.Scanner.
type Client struct {
	baseURL    string
	token      string
	project    string
	httpClient *http.Client
}

// New returns a Client that calls F5's Scan API at baseURL, authenticating with token
// and scoping scans to project. Each Scan call is bounded by timeout.
func New(baseURL, token, project string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		project: project,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// scanRequest is the JSON body sent to F5's Scan API.
type scanRequest struct {
	Input         string `json:"input"`
	Project       string `json:"project"`
	ScanDirection string `json:"scanDirection"`
	FlagOnly      bool   `json:"flagOnly"`
	Verbose       bool   `json:"verbose"`
}

// scannerResult is one scanner's contribution to a scan response.
type scannerResult struct {
	ScannerVersionMeta struct {
		Name string `json:"name"`
	} `json:"scannerVersionMeta"`
	ScannerID string `json:"scannerId"`
}

// scanResponse is the JSON body returned by F5's Scan API.
type scanResponse struct {
	Result struct {
		Outcome        string          `json:"outcome"`
		ScannerResults []scannerResult `json:"scannerResults"`
	} `json:"result"`
	RedactedInput string `json:"redactedInput"`
}

// Scan sends text to F5's Scan API for the given direction ("request" or "response")
// and returns the resulting guard.ScanResult. It returns an error if the request
// cannot be built or sent, the response status is not 2xx, or the response body
// cannot be decoded.
func (c *Client) Scan(ctx context.Context, text, direction string) (guard.ScanResult, error) {
	reqBody, err := json.Marshal(scanRequest{
		Input:         text,
		Project:       c.project,
		ScanDirection: direction,
		FlagOnly:      false,
		Verbose:       true,
	})
	if err != nil {
		return guard.ScanResult{}, fmt.Errorf("marshal scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+scanPath, bytes.NewReader(reqBody))
	if err != nil {
		return guard.ScanResult{}, fmt.Errorf("build scan request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("f5client: scan call failed: %v", err)
		return guard.ScanResult{}, fmt.Errorf("call F5 scan API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("f5client: scan API returned status %d, body: %s", resp.StatusCode, truncatedBody(resp.Body))
		return guard.ScanResult{}, fmt.Errorf("F5 scan API returned status %d", resp.StatusCode)
	}

	var parsed scanResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		log.Printf("f5client: decode scan response failed: %v", err)
		return guard.ScanResult{}, fmt.Errorf("decode scan response: %w", err)
	}

	if parsed.Result.Outcome == "" {
		log.Printf("f5client: scan response had empty result.outcome for direction %q; response shape may not match what this client expects", direction)
	}

	return guard.ScanResult{
		Outcome:       parsed.Result.Outcome,
		RedactedInput: parsed.RedactedInput,
		Reason:        reasonFromScannerResults(parsed.Result.ScannerResults),
	}, nil
}

// truncatedBody reads up to maxLoggedBodyBytes from r for inclusion in a log
// line, so a large or runaway F5 response body is never dumped in full.
func truncatedBody(r io.Reader) string {
	limited, err := io.ReadAll(io.LimitReader(r, maxLoggedBodyBytes))
	if err != nil {
		return "<unreadable body>"
	}
	return string(limited)
}

// reasonFromScannerResults names each scanner result (preferring its version-meta
// name, then its scanner ID, then the literal "scanner") and joins the names with
// ", ". It returns defaultReason when there are no scanner results to name.
func reasonFromScannerResults(results []scannerResult) string {
	if len(results) == 0 {
		return defaultReason
	}

	names := make([]string, len(results))
	for i, result := range results {
		switch {
		case result.ScannerVersionMeta.Name != "":
			names[i] = result.ScannerVersionMeta.Name
		case result.ScannerID != "":
			names[i] = result.ScannerID
		default:
			names[i] = "scanner"
		}
	}
	return strings.Join(names, ", ")
}
