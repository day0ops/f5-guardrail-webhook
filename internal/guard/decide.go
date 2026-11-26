package guard

import (
	"context"
	"fmt"
	"strings"
)

// ScanResult holds the outcome of a text scan from the F5 AI Guardrails service,
// including the security classification, any redacted input, and the reason for the decision.
type ScanResult struct {
	Outcome       string
	RedactedInput string
	Reason        string
}

// Scanner defines the interface for text scanning implementations that return a ScanResult.
type Scanner interface {
	Scan(ctx context.Context, text, direction string) (ScanResult, error)
}

// Action describes an HTTP response or body transformation to apply in response to a scan result.
type Action struct {
	Body       any    `json:"body,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// ActionResponse wraps an Action for HTTP serialization.
type ActionResponse struct {
	Action Action `json:"action"`
}

// IsBlockedOutcome reports whether the outcome string indicates content was blocked, flagged, or rejected.
// The check is case-insensitive.
func IsBlockedOutcome(outcome string) bool {
	lower := strings.ToLower(outcome)
	return lower == "blocked" || lower == "flagged" || lower == "rejected"
}

// DecideRequest returns an Action for a request based on its scan result. It rejects requests
// with blocked/flagged/rejected outcomes, masks requests with redacted input, and passes others.
func DecideRequest(body ChatRequestBody, scan ScanResult) ActionResponse {
	if IsBlockedOutcome(scan.Outcome) {
		message := fmt.Sprintf("Blocked by F5 AI Guardrails: %s", scan.Reason)
		return ActionResponse{
			Action: Action{
				Body:       message,
				StatusCode: 403,
				Reason:     message,
			},
		}
	}

	originalText := PromptText(body)
	if scan.RedactedInput != "" && scan.RedactedInput != originalText {
		maskedBody := ReplaceLastUserMessage(body, scan.RedactedInput)
		return ActionResponse{
			Action: Action{
				Body:   maskedBody,
				Reason: "Redacted by F5 AI Guardrails",
			},
		}
	}

	return ActionResponse{
		Action: Action{
			Reason: "cleared",
		},
	}
}

// DecideResponse returns an Action for a response based on its scan result. It never rejects
// responses, but masks blocked/flagged/rejected or redacted content with empty or redacted text.
func DecideResponse(body ChatResponseBody, scan ScanResult) ActionResponse {
	if IsBlockedOutcome(scan.Outcome) {
		maskedBody := ReplaceAllChoiceContent(body, "")
		return ActionResponse{
			Action: Action{
				Body:   maskedBody,
				Reason: fmt.Sprintf("Blocked by F5 AI Guardrails: %s", scan.Reason),
			},
		}
	}

	originalText := ResponseText(body)
	if scan.RedactedInput != "" && scan.RedactedInput != originalText {
		maskedBody := ReplaceAllChoiceContent(body, scan.RedactedInput)
		return ActionResponse{
			Action: Action{
				Body:   maskedBody,
				Reason: "Redacted by F5 AI Guardrails",
			},
		}
	}

	return ActionResponse{
		Action: Action{
			Reason: "cleared",
		},
	}
}
