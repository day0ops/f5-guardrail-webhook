// Package server implements the HTTP webhook contract agentgateway's
// promptGuard expects: GET /healthz, POST /request, POST /response. It
// scans chat bodies through a guard.Scanner and turns the result into a
// guard.ActionResponse that tells agentgateway whether to pass, mask, or
// reject the traffic.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/day0ops/f5-guardrail-webhook/internal/guard"
)

// Severity ranks for combining several scanned messages/choices into one
// overall outcome: a block ranks above a redaction-driven mask, which ranks
// above a clean pass. The combining loops use this so their final logged
// outcome (and, for /response, the mask reason) reflects the most severe
// thing seen across every message/choice scanned, not whichever one happened
// to be scanned last.
const (
	severityClean = iota
	severityMasked
	severityBlocked
)

// Server wires a guard.Scanner into agentgateway's promptGuard webhook
// contract. It is decoupled from any concrete scanner implementation.
type Server struct {
	scanner   guard.Scanner
	batchScan bool
}

// New returns a Server that scans request and response bodies using scanner.
//
// By default (batchScan false, SCAN_MODE=gated), a multi-message conversation
// is first gated by one scan of the whole joined blob to decide block/no-block
// with full cross-turn context, then every message/choice is scanned and
// decided on individually so a mask only ever rewrites the one message/choice
// that needs it; a single-message body has no cross-message context to
// protect, so it skips the gate and goes straight to that per-message scan.
// When batchScan is true (SCAN_MODE=batch), each direction's whole
// conversation is joined into one blob and scanned in a single call instead,
// with no gate and no per-message follow-up - cheaper, but a mask can only
// overwrite one whole message, so it is only safe for single-turn prompts.
func New(scanner guard.Scanner, batchScan bool) *Server {
	return &Server{scanner: scanner, batchScan: batchScan}
}

// Routes returns the HTTP handler exposing the webhook's healthz, request,
// and response endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /request", s.handleRequest)
	mux.HandleFunc("POST /response", s.handleResponse)
	return mux
}

// handleHealthz reports that the server is up.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

// requestEnvelope is the JSON envelope agentgateway posts to /request.
type requestEnvelope struct {
	Body guard.ChatRequestBody `json:"body"`
}

// handleRequest scans a chat request's prompt text and writes the resulting
// pass/mask/reject action. The transport-level HTTP status is always 200;
// the semantic decision lives only in the JSON action body, since agentgateway
// reads the decision from there rather than from the HTTP status.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	var envelope requestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		logDecision("request", "n/a", "reject", 0, 0)
		writeJSON(w, rejectAction(http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	decideFn := s.decideRequestGated
	if s.batchScan {
		decideFn = s.decideRequestBatch
	}
	decision, outcome, scanned, masked := decideFn(r.Context(), envelope.Body)

	logDecision("request", outcome, actionKind(decision.Action), scanned, masked)
	writeJSON(w, decision)
}

// decideRequestBatch joins the whole request body into one prompt and scans
// it in a single call, the opt-in SCAN_MODE=batch behavior. It returns the
// resulting action, the scan outcome ("n/a" when the scan call itself
// failed), and the scan/mask counts for the caller's single decision log.
func (s *Server) decideRequestBatch(ctx context.Context, body guard.ChatRequestBody) (guard.ActionResponse, string, int, int) {
	scanResult, err := s.scanner.Scan(ctx, guard.PromptText(body), "request")
	if err != nil {
		reason := fmt.Sprintf("F5 AI Guardrails request scan failed: %v", err)
		return rejectAction(http.StatusServiceUnavailable, reason), "n/a", 1, 0
	}

	decision := guard.DecideRequest(body, scanResult)
	masked := 0
	if actionKind(decision.Action) == "mask" {
		masked = 1 // a batch mask only ever overwrites the last user message.
	}
	return decision, scanResult.Outcome, 1, masked
}

// decideRequestGated implements the default scanning mode. A single-message
// body has no cross-message context to protect, so it goes straight to the
// per-message loop (decideRequestPerMessage), costing exactly what it always
// did. A multi-message body is first gated by one scan of the whole joined
// conversation, purely to decide block/no-block with full context: a gate
// scan failure rejects, and a gate block rejects immediately on the full
// body - zero per-message calls spent. Otherwise, the gate's own
// RedactedInput (if any) is discarded and the per-message loop runs exactly
// as it would have without a gate, so it can still independently reject or
// mask individual messages (defense in depth).
func (s *Server) decideRequestGated(ctx context.Context, body guard.ChatRequestBody) (guard.ActionResponse, string, int, int) {
	if len(body.Messages) <= 1 {
		return s.decideRequestPerMessage(ctx, body)
	}

	gateResult, err := s.scanner.Scan(ctx, guard.PromptText(body), "request")
	if err != nil {
		reason := fmt.Sprintf("F5 AI Guardrails request scan failed: %v", err)
		return rejectAction(http.StatusServiceUnavailable, reason), "n/a", 1, 0
	}
	if guard.IsBlockedOutcome(gateResult.Outcome) {
		return guard.DecideRequest(body, gateResult), gateResult.Outcome, 1, 0
	}

	decision, outcome, scanned, masked := s.decideRequestPerMessage(ctx, body)
	return decision, outcome, scanned + 1, masked
}

// decideRequestPerMessage scans each message in body individually and
// combines the per-message decisions into one overall action: it rejects
// immediately on the first blocked message (stopping without scanning the
// rest), or masks only the messages that needed redaction while leaving the
// others untouched. It returns the resulting action, the most severe outcome
// seen across the messages actually scanned ("n/a" when body has no
// messages), and the number of scan calls made and messages masked, for the
// caller's single decision log.
func (s *Server) decideRequestPerMessage(ctx context.Context, body guard.ChatRequestBody) (guard.ActionResponse, string, int, int) {
	if len(body.Messages) == 0 {
		return passAction(), "n/a", 0, 0
	}

	messages := make([]guard.ChatMessage, len(body.Messages))
	copy(messages, body.Messages)

	maskedCount := 0
	outcome := "n/a"
	severity := -1

	for i, msg := range body.Messages {
		scanResult, err := s.scanner.Scan(ctx, msg.Content, "request")
		if err != nil {
			reason := fmt.Sprintf("F5 AI Guardrails request scan failed: %v", err)
			// masked=0: this rejects, so nothing in this response was masked.
			return rejectAction(http.StatusServiceUnavailable, reason), "n/a", i + 1, 0
		}

		singleBody := guard.ChatRequestBody{Messages: []guard.ChatMessage{msg}}
		decision := guard.DecideRequest(singleBody, scanResult)
		if decision.Action.StatusCode != 0 {
			// masked=0: this rejects, so nothing in this response was masked.
			return decision, scanResult.Outcome, i + 1, 0
		}

		masked := false
		if content, m := singleRequestMaskedContent(decision); m {
			messages[i].Content = content
			maskedCount++
			masked = true
		}
		if level := severityLevel(scanResult.Outcome, masked); level > severity {
			severity = level
			outcome = scanResult.Outcome
		}
	}

	if maskedCount == 0 {
		return passAction(), outcome, len(body.Messages), 0
	}
	return guard.ActionResponse{
		Action: guard.Action{
			Body:   guard.ChatRequestBody{Messages: messages},
			Reason: "Redacted by F5 AI Guardrails",
		},
	}, outcome, len(body.Messages), maskedCount
}

// singleRequestMaskedContent extracts the redacted content of a per-message
// mask decision's single-message body, reporting false if decision carries no
// mask (a pass, or a reject already handled by the caller).
func singleRequestMaskedContent(decision guard.ActionResponse) (string, bool) {
	maskedBody, ok := decision.Action.Body.(guard.ChatRequestBody)
	if !ok || len(maskedBody.Messages) == 0 {
		return "", false
	}
	return maskedBody.Messages[0].Content, true
}

// responseEnvelope is the JSON envelope agentgateway posts to /response.
type responseEnvelope struct {
	Body guard.ChatResponseBody `json:"body"`
}

// handleResponse scans a chat response's text and writes the resulting
// pass/mask action. Unlike /request, this path never rejects with a
// status_code: a response has already been generated upstream, so a
// malformed body or a scan failure masks the response content instead of
// rejecting it, meaning neither can surface as a raw 5xx to agentgateway.
func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	var envelope responseEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		logDecision("response", "n/a", "mask", 0, 0)
		writeJSON(w, maskAction(envelope.Body, fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	decideFn := s.decideResponseGated
	if s.batchScan {
		decideFn = s.decideResponseBatch
	}
	decision, outcome, scanned, masked := decideFn(r.Context(), envelope.Body)

	logDecision("response", outcome, actionKind(decision.Action), scanned, masked)
	writeJSON(w, decision)
}

// decideResponseBatch joins the whole response body into one blob and scans
// it in a single call, the opt-in SCAN_MODE=batch behavior. It returns the
// resulting action, the scan outcome ("n/a" when the scan call itself
// failed), and the scan/mask counts for the caller's single decision log.
func (s *Server) decideResponseBatch(ctx context.Context, body guard.ChatResponseBody) (guard.ActionResponse, string, int, int) {
	scanResult, err := s.scanner.Scan(ctx, guard.ResponseText(body), "response")
	if err != nil {
		reason := fmt.Sprintf("F5 AI Guardrails response scan failed: %v", err)
		return maskAction(body, reason), "n/a", 1, len(body.Choices)
	}

	decision := guard.DecideResponse(body, scanResult)
	masked := 0
	if actionKind(decision.Action) == "mask" {
		masked = len(body.Choices) // a batch mask always overwrites every choice.
	}
	return decision, scanResult.Outcome, 1, masked
}

// decideResponseGated mirrors decideRequestGated for the response direction.
// A single-choice body skips the gate and goes straight to the per-choice
// loop (decideResponsePerMessage). A multi-choice body is first gated by one
// scan of the whole joined response, purely to decide block/no-block with
// full context. Unlike the request direction, a gate scan failure or a gate
// block never rejects: a scan failure masks (fail-closed, matching every
// other response-side scan failure), and a gate block masks the whole
// response to empty via guard.DecideResponse, matching old batch mode's
// mask-on-block behavior and preserving the existing request/response
// asymmetry (response never rejects). Otherwise, the gate's own
// RedactedInput (if any) is discarded and the per-choice loop runs exactly
// as it would have without a gate (defense in depth).
func (s *Server) decideResponseGated(ctx context.Context, body guard.ChatResponseBody) (guard.ActionResponse, string, int, int) {
	if len(body.Choices) <= 1 {
		return s.decideResponsePerMessage(ctx, body)
	}

	gateResult, err := s.scanner.Scan(ctx, guard.ResponseText(body), "response")
	if err != nil {
		reason := fmt.Sprintf("F5 AI Guardrails response scan failed: %v", err)
		return maskAction(body, reason), "n/a", 1, len(body.Choices)
	}
	if guard.IsBlockedOutcome(gateResult.Outcome) {
		return guard.DecideResponse(body, gateResult), gateResult.Outcome, 1, len(body.Choices)
	}

	decision, outcome, scanned, masked := s.decideResponsePerMessage(ctx, body)
	return decision, outcome, scanned + 1, masked
}

// decideResponsePerMessage scans each choice in body individually and
// combines the per-choice decisions into one overall action: unlike the
// request path it never rejects, so every choice is scanned even after one
// comes back blocked (that choice is simply masked to empty in place). If any
// scan call itself fails, it conservatively masks every choice to empty,
// matching the fail-closed behavior of a whole-body scan failure. The combined
// mask's reason reflects the most severe thing seen across every choice
// scanned: if any choice was blocked, the reason names it ("Blocked by F5 AI
// Guardrails: <reason>", the same format as a rejected request and the gate's
// own block); otherwise, if any choice was merely redacted, the reason is the
// generic "Redacted by F5 AI Guardrails". It returns the resulting action,
// that most severe outcome ("n/a" when body has no choices, or when a scan
// call itself failed), and the number of scan calls made and choices masked,
// for the caller's single decision log.
func (s *Server) decideResponsePerMessage(ctx context.Context, body guard.ChatResponseBody) (guard.ActionResponse, string, int, int) {
	if len(body.Choices) == 0 {
		return passAction(), "n/a", 0, 0
	}

	choices := make([]guard.ChatChoice, len(body.Choices))
	copy(choices, body.Choices)

	maskedCount := 0
	outcome := "n/a"
	severity := -1
	// blockedReason only updates on a strict severity increase (see
	// severityLevel below), so when several choices are blocked, this holds
	// the first-encountered one's reason, left-to-right - deterministic, and
	// intentional, not an oversight.
	blockedReason := ""

	for i, choice := range body.Choices {
		scanResult, err := s.scanner.Scan(ctx, choice.Message.Content, "response")
		if err != nil {
			reason := fmt.Sprintf("F5 AI Guardrails response scan failed: %v", err)
			// maskAction masks every choice in body, not just the ones masked
			// so far in this loop, so the count must match: len(body.Choices).
			return maskAction(body, reason), "n/a", i + 1, len(body.Choices)
		}

		singleBody := guard.ChatResponseBody{Choices: []guard.ChatChoice{choice}}
		decision := guard.DecideResponse(singleBody, scanResult)
		masked := false
		if content, m := singleResponseMaskedContent(decision); m {
			choices[i].Message.Content = content
			maskedCount++
			masked = true
		}

		if level := severityLevel(scanResult.Outcome, masked); level > severity {
			severity = level
			outcome = scanResult.Outcome
			if guard.IsBlockedOutcome(scanResult.Outcome) {
				blockedReason = scanResult.Reason
			}
		}
	}

	if maskedCount == 0 {
		return passAction(), outcome, len(body.Choices), 0
	}

	reason := "Redacted by F5 AI Guardrails"
	if severity == severityBlocked {
		reason = fmt.Sprintf("Blocked by F5 AI Guardrails: %s", blockedReason)
	}
	return guard.ActionResponse{
		Action: guard.Action{
			Body:   guard.ChatResponseBody{Choices: choices},
			Reason: reason,
		},
	}, outcome, len(body.Choices), maskedCount
}

// severityLevel ranks one scanned message/choice for combining several scans
// into one overall outcome: a block ranks above a redaction-driven mask,
// which ranks above a clean pass.
func severityLevel(outcome string, masked bool) int {
	switch {
	case guard.IsBlockedOutcome(outcome):
		return severityBlocked
	case masked:
		return severityMasked
	default:
		return severityClean
	}
}

// singleResponseMaskedContent extracts the masked content of a per-choice
// mask decision's single-choice body, reporting false if decision carries no
// mask (a pass).
func singleResponseMaskedContent(decision guard.ActionResponse) (string, bool) {
	maskedBody, ok := decision.Action.Body.(guard.ChatResponseBody)
	if !ok || len(maskedBody.Choices) == 0 {
		return "", false
	}
	return maskedBody.Choices[0].Message.Content, true
}

// passAction builds a pass ActionResponse: no body, reason "cleared". Mirrors
// guard.DecideRequest/guard.DecideResponse's own pass action, since combining
// per-message decisions still needs a pass result when none of them mask or
// reject, but has no single guard call left to produce one.
func passAction() guard.ActionResponse {
	return guard.ActionResponse{
		Action: guard.Action{
			Reason: "cleared",
		},
	}
}

// rejectAction builds a reject ActionResponse carrying the same text as both
// the body and the reason.
func rejectAction(statusCode int, message string) guard.ActionResponse {
	return guard.ActionResponse{
		Action: guard.Action{
			Body:       message,
			StatusCode: statusCode,
			Reason:     message,
		},
	}
}

// maskAction builds a mask ActionResponse that replaces every choice's
// content in body, carrying no status_code since the response path never
// rejects.
func maskAction(body guard.ChatResponseBody, reason string) guard.ActionResponse {
	return guard.ActionResponse{
		Action: guard.Action{
			Body:   guard.ReplaceAllChoiceContent(body, ""),
			Reason: reason,
		},
	}
}

// logDecision logs exactly one line per webhook decision: the direction
// ("request" or "response"), the most severe scan outcome seen ("n/a" when no
// scan ran), the resulting action kind, and how many scan calls it took to
// reach it and how many messages/choices ended up masked. It never logs
// message content or secrets.
func logDecision(direction, outcome, kind string, scanned, masked int) {
	log.Printf("server: direction=%s outcome=%q action=%s scanned=%d masked=%d", direction, outcome, kind, scanned, masked)
}

// actionKind classifies an action as "reject", "mask", or "pass" for logging.
func actionKind(action guard.Action) string {
	switch {
	case action.StatusCode != 0:
		return "reject"
	case action.Body != nil:
		return "mask"
	default:
		return "pass"
	}
}

// writeJSON writes v as a JSON body with HTTP 200. Per the webhook contract,
// this server always answers with transport status 200; any reject or mask
// decision is encoded in the JSON body instead.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
