package guard

import "testing"

func TestPromptText_JoinsMessagesWithNewline(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{
		{Role: "system", Content: "be nice"},
		{Role: "user", Content: "hello"},
	}}
	got := PromptText(body)
	want := "be nice\nhello"
	if got != want {
		t.Fatalf("PromptText() = %q, want %q", got, want)
	}
}

func TestPromptText_EmptyMessagesReturnsEmptyString(t *testing.T) {
	if got := PromptText(ChatRequestBody{}); got != "" {
		t.Fatalf("PromptText() = %q, want empty string", got)
	}
}

func TestResponseText_JoinsChoicesWithNewline(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{
		{Message: ChatMessage{Content: "first"}},
		{Message: ChatMessage{Content: "second"}},
	}}
	if got, want := ResponseText(body), "first\nsecond"; got != want {
		t.Fatalf("ResponseText() = %q, want %q", got, want)
	}
}

func TestReplaceLastUserMessage_ReplacesLastUserRoleOnly(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "first user turn"},
		{Role: "assistant", Content: "reply"},
		{Role: "user", Content: "second user turn"},
	}}
	got := ReplaceLastUserMessage(body, "REDACTED")
	if got.Messages[3].Content != "REDACTED" {
		t.Fatalf("expected last user message replaced, got %q", got.Messages[3].Content)
	}
	if got.Messages[1].Content != "first user turn" {
		t.Fatalf("expected first user message untouched, got %q", got.Messages[1].Content)
	}
}

func TestReplaceLastUserMessage_FallsBackToLastMessageWhenNoUserRole(t *testing.T) {
	body := ChatRequestBody{Messages: []ChatMessage{
		{Role: "system", Content: "sys"},
		{Role: "assistant", Content: "reply"},
	}}
	got := ReplaceLastUserMessage(body, "REDACTED")
	if got.Messages[len(got.Messages)-1].Content != "REDACTED" {
		t.Fatalf("expected last message replaced as fallback")
	}
}

func TestReplaceLastUserMessage_EmptyMessagesReturnsUnchanged(t *testing.T) {
	got := ReplaceLastUserMessage(ChatRequestBody{}, "REDACTED")
	if len(got.Messages) != 0 {
		t.Fatalf("expected no messages, got %d", len(got.Messages))
	}
}

func TestReplaceAllChoiceContent_ReplacesEveryChoice(t *testing.T) {
	body := ChatResponseBody{Choices: []ChatChoice{
		{Message: ChatMessage{Content: "a"}},
		{Message: ChatMessage{Content: "b"}},
	}}
	got := ReplaceAllChoiceContent(body, "")
	for i, c := range got.Choices {
		if c.Message.Content != "" {
			t.Fatalf("choice %d not replaced: %q", i, c.Message.Content)
		}
	}
}
