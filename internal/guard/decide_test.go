package guard

import "testing"

func TestIsBlockedOutcome_TrueForBlockedFlaggedRejectedCaseInsensitive(t *testing.T) {
	for _, outcome := range []string{"blocked", "Flagged", "REJECTED"} {
		if !IsBlockedOutcome(outcome) {
			t.Fatalf("IsBlockedOutcome(%q) = false, want true", outcome)
		}
	}
}

func TestIsBlockedOutcome_FalseForClean(t *testing.T) {
	for _, outcome := range []string{"", "clean", "allowed"} {
		if IsBlockedOutcome(outcome) {
			t.Fatalf("IsBlockedOutcome(%q) = true, want false", outcome)
		}
	}
}

func TestDecideRequest_PassesWhenCleanAndNoRedaction(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	got := DecideRequest(body, ScanResult{Outcome: "clean"})
	if got.Action.StatusCode != 0 || got.Action.Body != nil || got.Action.Reason != "cleared" {
		t.Fatalf("expected pass action, got %+v", got.Action)
	}
}

func TestDecideRequest_RejectsWhenBlocked(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	got := DecideRequest(body, ScanResult{Outcome: "blocked", Reason: "toxicity"})
	if got.Action.StatusCode != 403 {
		t.Fatalf("expected status_code 403, got %d", got.Action.StatusCode)
	}
	if got.Action.Body != "Blocked by F5 AI Guardrails: toxicity" {
		t.Fatalf("unexpected reject body: %v", got.Action.Body)
	}
}

func TestDecideRequest_RejectsWhenFlagged(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	got := DecideRequest(body, ScanResult{Outcome: "flagged", Reason: "pii"})
	if got.Action.StatusCode != 403 {
		t.Fatalf("flagged outcome did not reject: %+v", got.Action)
	}
}

func TestDecideRequest_MasksWhenRedactedInputDiffers(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{{Role: "user", Content: "my ssn is 123-45-6789"}}}
	got := DecideRequest(body, ScanResult{Outcome: "clean", RedactedInput: "my ssn is [REDACTED]"})
	if got.Action.StatusCode != 0 {
		t.Fatalf("expected mask, not reject: %+v", got.Action)
	}
	masked, ok := got.Action.Body.(ChatRequestBody)
	if !ok || masked.Messages[0].Content != "my ssn is [REDACTED]" {
		t.Fatalf("expected masked body with redacted content, got %+v", got.Action.Body)
	}
}

func TestDecideRequest_PassesWhenRedactedInputEqualsOriginal(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	got := DecideRequest(body, ScanResult{Outcome: "clean", RedactedInput: "hi"})
	if got.Action.Reason != "cleared" {
		t.Fatalf("expected pass when redactedInput equals original, got %+v", got.Action)
	}
}

func TestDecideResponse_PassesWhenClean(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{{Message: ChatMessage{Content: "hi"}}}}
	got := DecideResponse(body, ScanResult{Outcome: "clean"})
	if got.Action.Reason != "cleared" {
		t.Fatalf("expected pass, got %+v", got.Action)
	}
}

func TestDecideResponse_MasksToEmptyWhenBlocked(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{{Message: ChatMessage{Content: "secret stuff"}}}}
	got := DecideResponse(body, ScanResult{Outcome: "blocked", Reason: "secrets"})
	if got.Action.StatusCode != 0 {
		t.Fatalf("response path must never reject, got status_code %d", got.Action.StatusCode)
	}
	masked, ok := got.Action.Body.(ChatResponseBody)
	if !ok || masked.Choices[0].Message.Content != "" {
		t.Fatalf("expected empty-content mask, got %+v", got.Action.Body)
	}
}

func TestDecideResponse_PassesWhenRedactedInputEqualsOriginal(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{{Message: ChatMessage{Content: "hi"}}}}
	got := DecideResponse(body, ScanResult{Outcome: "clean", RedactedInput: "hi"})
	if got.Action.Reason != "cleared" {
		t.Fatalf("expected pass when redactedInput equals original, got %+v", got.Action)
	}
}

func TestDecideResponse_MasksWithRedactedContentWhenDiffers(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{{Message: ChatMessage{Content: "call 555-1234"}}}}
	got := DecideResponse(body, ScanResult{Outcome: "clean", RedactedInput: "call [REDACTED]"})
	masked, ok := got.Action.Body.(ChatResponseBody)
	if !ok || masked.Choices[0].Message.Content != "call [REDACTED]" {
		t.Fatalf("expected redacted content, got %+v", got.Action.Body)
	}
}
