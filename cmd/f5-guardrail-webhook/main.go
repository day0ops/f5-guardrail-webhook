// Command f5-guardrail-webhook runs the HTTP adapter that sits behind
// agentgateway's promptGuard webhook and calls F5 AI Guardrails' Scan API.
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/day0ops/f5-guardrail-webhook/internal/f5client"
	"github.com/day0ops/f5-guardrail-webhook/internal/server"
)

// defaultPort is used when PORT is unset.
const defaultPort = "8000"

// defaultScanTimeout is used when SCAN_TIMEOUT_SECONDS is unset or invalid.
const defaultScanTimeout = 15 * time.Second

func main() {
	baseURL := requireEnv("F5_AISEC_URL")
	token := requireEnv("F5_AISEC_TOKEN")
	project := requireEnv("CAI_PROJECT")

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	timeout := scanTimeout()
	batchScan := scanModeIsBatch()

	client := f5client.New(baseURL, token, project, timeout)
	srv := server.New(client, batchScan)

	log.Printf("f5-guardrail-webhook listening on :%s", port)
	if err := http.ListenAndServe(":"+port, srv.Routes()); err != nil {
		log.Fatalf("f5-guardrail-webhook: %v", err)
	}
}

// requireEnv returns the value of the named environment variable, or exits
// with a fatal error naming it if it is unset or empty.
func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("missing required environment variable %s", name)
	}
	return value
}

// scanTimeout reads SCAN_TIMEOUT_SECONDS and converts it to a time.Duration,
// falling back to defaultScanTimeout when it is unset or not a valid integer.
func scanTimeout() time.Duration {
	raw := os.Getenv("SCAN_TIMEOUT_SECONDS")
	if raw == "" {
		return defaultScanTimeout
	}

	seconds, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid SCAN_TIMEOUT_SECONDS %q, falling back to %s: %v", raw, defaultScanTimeout, err)
		return defaultScanTimeout
	}
	if seconds <= 0 {
		log.Printf("SCAN_TIMEOUT_SECONDS %q must be positive, falling back to %s", raw, defaultScanTimeout)
		return defaultScanTimeout
	}

	return time.Duration(seconds) * time.Second
}

// scanModeIsBatch reads SCAN_MODE and reports whether it selects batch
// scanning (SCAN_MODE=batch) rather than gated scanning (SCAN_MODE=gated, the
// default when unset). Unlike scanTimeout, a set-but-invalid value is a fatal
// misconfiguration rather than a silent fallback: SCAN_MODE picks between
// materially different scanning behaviors, so silently defaulting could mask
// a deployment mistake in production.
func scanModeIsBatch() bool {
	raw := os.Getenv("SCAN_MODE")
	switch strings.ToLower(raw) {
	case "", "gated":
		return false
	case "batch":
		return true
	}

	log.Fatalf("invalid SCAN_MODE %q: must be %q or %q", raw, "gated", "batch")
	return false
}
