// Package guard holds domain types and pure decision logic for turning an F5
// AI Guardrails scan result into a pass/mask/reject action. It has no I/O.
package guard

import "strings"

// ChatMessage represents a single message in a chat exchange with a role and content.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequestBody wraps a list of messages for an LLM request.
type ChatRequestBody struct {
	Messages []ChatMessage `json:"messages"`
}

// ChatChoice represents a single response choice from an LLM completion with its message.
type ChatChoice struct {
	Message ChatMessage `json:"message"`
}

// ChatResponseBody wraps a list of response choices for an LLM response.
type ChatResponseBody struct {
	Choices []ChatChoice `json:"choices"`
}

// PromptText extracts and joins all message content from a request body into a newline-separated string.
func PromptText(body ChatRequestBody) string {
	if len(body.Messages) == 0 {
		return ""
	}
	var contents []string
	for _, msg := range body.Messages {
		contents = append(contents, msg.Content)
	}
	return strings.Join(contents, "\n")
}

// ResponseText extracts and joins all choice content from a response body into a newline-separated string.
func ResponseText(body ChatResponseBody) string {
	if len(body.Choices) == 0 {
		return ""
	}
	var contents []string
	for _, choice := range body.Choices {
		contents = append(contents, choice.Message.Content)
	}
	return strings.Join(contents, "\n")
}

// ReplaceLastUserMessage replaces the last user message in a request body with new content, or the final message if no user role is found.
func ReplaceLastUserMessage(body ChatRequestBody, content string) ChatRequestBody {
	if len(body.Messages) == 0 {
		return body
	}

	messages := make([]ChatMessage, len(body.Messages))
	copy(messages, body.Messages)

	lastUserIdx := -1
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			lastUserIdx = i
			break
		}
	}

	if lastUserIdx >= 0 {
		messages[lastUserIdx].Content = content
	} else {
		messages[len(messages)-1].Content = content
	}

	return ChatRequestBody{Messages: messages}
}

// ReplaceAllChoiceContent replaces the content of all choices in a response body with the provided text.
func ReplaceAllChoiceContent(body ChatResponseBody, content string) ChatResponseBody {
	choices := make([]ChatChoice, len(body.Choices))
	for i, choice := range body.Choices {
		choices[i] = ChatChoice{
			Message: ChatMessage{
				Role:    choice.Message.Role,
				Content: content,
			},
		}
	}
	return ChatResponseBody{Choices: choices}
}
