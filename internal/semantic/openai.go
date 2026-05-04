package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultOpenAIEndpoint = "https://api.openai.com/v1/chat/completions"

// OpenAIClassifier calls an OpenAI-compatible chat completion endpoint and
// expects a strict JSON object with MCPIDS labels, score, and reasoning.
type OpenAIClassifier struct {
	endpoint       string
	bearerToken    string
	model          string
	client         *http.Client
	fallbackToStub bool
	stub           Classifier
}

// NewOpenAIClassifier creates an OpenAI-compatible classifier backend.
func NewOpenAIClassifier(opts Options) (Classifier, error) {
	endpoint := strings.TrimSpace(opts.Endpoint)
	if endpoint == "" {
		endpoint = defaultOpenAIEndpoint
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = "gpt-4.1-mini"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &OpenAIClassifier{
		endpoint:       endpoint,
		bearerToken:    strings.TrimSpace(opts.BearerToken),
		model:          model,
		client:         &http.Client{Timeout: timeout},
		fallbackToStub: opts.FallbackToStub,
		stub:           NewStubClassifier(),
	}, nil
}

// Name implements Classifier.
func (c *OpenAIClassifier) Name() string {
	return "openai:" + c.model
}

// Classify implements Classifier.
func (c *OpenAIClassifier) Classify(ctx context.Context, req ClassifyRequest) (*Result, error) {
	if c.bearerToken == "" {
		return c.fallback(req, fmt.Errorf("semantic: openai bearer token is not configured"))
	}

	prompt := buildOpenAIClassifierPrompt(req)
	payload := map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a security classifier for MCP traffic. Return one JSON object only, with keys labels, risk_score, confidence, reasoning, and model_used. labels must be an array of objects with name, confidence, and evidence. Allowed label names are prompt_injection, indirect_injection, credential_leak, pii_email, pii_ssn, pii_credit_card, pii_phone, data_exfiltration, tool_poisoning, ssrf_attempt, command_injection, privilege_escalation, shadow_tool, secrecy_language, authority_override.",
			},
			{"role": "user", "content": prompt},
		},
		"temperature":     0,
		"response_format": map[string]string{"type": "json_object"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("semantic: encode openai request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("semantic: build openai request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.bearerToken)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return c.fallback(req, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return c.fallback(req, fmt.Errorf("semantic: read openai response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.fallback(req, fmt.Errorf("semantic: openai backend returned %s: %s", resp.Status, strings.TrimSpace(string(respBody))))
	}

	result, err := parseOpenAIClassifierResponse(respBody)
	if err != nil {
		return c.fallback(req, err)
	}
	if result.ModelUsed == "" {
		result.ModelUsed = c.Name()
	}
	return result, nil
}

// ClassifyAsync implements Classifier.
func (c *OpenAIClassifier) ClassifyAsync(ctx context.Context, req ClassifyRequest, cb func(*Result, error)) {
	go func() {
		result, err := c.Classify(ctx, req)
		cb(result, err)
	}()
}

func (c *OpenAIClassifier) fallback(req ClassifyRequest, cause error) (*Result, error) {
	if !c.fallbackToStub {
		return nil, cause
	}
	result, err := c.stub.Classify(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("semantic: openai backend failed (%v), stub fallback failed: %w", cause, err)
	}
	if result != nil {
		if result.Reasoning == "" {
			result.Reasoning = "openai backend unavailable; stub fallback used"
		}
		if result.ModelUsed == "" || result.ModelUsed == "stub" {
			result.ModelUsed = "stub-fallback"
		}
	}
	return result, nil
}

func buildOpenAIClassifierPrompt(req ClassifyRequest) string {
	var sb strings.Builder
	sb.WriteString("Classify this MCP content for security risk.\n")
	sb.WriteString("content_type: ")
	sb.WriteString(string(req.ContentType))
	sb.WriteString("\n")
	if len(req.Hints) > 0 {
		sb.WriteString("hints: ")
		sb.WriteString(strings.Join(req.Hints, ", "))
		sb.WriteString("\n")
	}
	if len(req.Context) > 0 {
		sb.WriteString("context:\n")
		for key, value := range req.Context {
			sb.WriteString("- ")
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("content:\n")
	sb.WriteString(req.Content)
	return sb.String()
}

func parseOpenAIClassifierResponse(body []byte) (*Result, error) {
	var envelope struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("semantic: decode openai envelope: %w", err)
	}
	if len(envelope.Choices) == 0 || strings.TrimSpace(envelope.Choices[0].Message.Content) == "" {
		return nil, fmt.Errorf("semantic: openai response has no message content")
	}

	var decoded struct {
		Labels []struct {
			Name       string   `json:"name"`
			Confidence float64  `json:"confidence"`
			Evidence   []string `json:"evidence"`
		} `json:"labels"`
		RiskScore  float64 `json:"risk_score"`
		Confidence float64 `json:"confidence"`
		Reasoning  string  `json:"reasoning"`
		ModelUsed  string  `json:"model_used"`
	}
	if err := json.Unmarshal([]byte(envelope.Choices[0].Message.Content), &decoded); err != nil {
		return nil, fmt.Errorf("semantic: decode openai classifier payload: %w", err)
	}

	result := &Result{
		RiskScore:  clamp01(decoded.RiskScore),
		Confidence: clamp01(decoded.Confidence),
		Reasoning:  decoded.Reasoning,
		ModelUsed:  strings.TrimSpace(decoded.ModelUsed),
	}
	if result.ModelUsed == "" {
		result.ModelUsed = strings.TrimSpace(envelope.Model)
	}
	for _, label := range decoded.Labels {
		if strings.TrimSpace(label.Name) == "" {
			continue
		}
		result.Labels = append(result.Labels, Label{
			Name:       label.Name,
			Confidence: clamp01(label.Confidence),
			Evidence:   append([]string(nil), label.Evidence...),
		})
	}
	return result, nil
}
