package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPTimeout = 2 * time.Second

// Options configures which semantic classifier backend to instantiate.
type Options struct {
	// Provider selects the classifier backend: "stub" or "http".
	Provider string

	// Endpoint is the HTTP classification endpoint when Provider is "http".
	Endpoint string

	// BearerToken is sent as Authorization: Bearer <token> for HTTP backends.
	BearerToken string

	// Model is forwarded to the HTTP backend for model selection.
	Model string

	// Timeout bounds each HTTP classification request.
	Timeout time.Duration

	// FallbackToStub keeps the pipeline available if the HTTP backend is unhealthy.
	FallbackToStub bool
}

// NewClassifier constructs the configured semantic classifier backend.
func NewClassifier(opts Options) (Classifier, error) {
	switch strings.ToLower(strings.TrimSpace(opts.Provider)) {
	case "", "stub":
		return NewStubClassifier(), nil
	case "http":
		return NewHTTPClassifier(opts)
	case "openai":
		return NewOpenAIClassifier(opts)
	default:
		return nil, fmt.Errorf("semantic: unsupported provider %q", opts.Provider)
	}
}

// HTTPClassifier calls a remote semantic classification service over HTTP.
type HTTPClassifier struct {
	endpoint       string
	bearerToken    string
	model          string
	client         *http.Client
	fallbackToStub bool
	stub           Classifier
}

// NewHTTPClassifier creates an HTTP-backed classifier.
func NewHTTPClassifier(opts Options) (Classifier, error) {
	if strings.TrimSpace(opts.Endpoint) == "" {
		return nil, fmt.Errorf("semantic: http endpoint is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &HTTPClassifier{
		endpoint:       opts.Endpoint,
		bearerToken:    strings.TrimSpace(opts.BearerToken),
		model:          strings.TrimSpace(opts.Model),
		client:         &http.Client{Timeout: timeout},
		fallbackToStub: opts.FallbackToStub,
		stub:           NewStubClassifier(),
	}, nil
}

// Name implements Classifier.
func (c *HTTPClassifier) Name() string {
	if c.model != "" {
		return "http:" + c.model
	}
	return "http"
}

// Classify implements Classifier.
func (c *HTTPClassifier) Classify(ctx context.Context, req ClassifyRequest) (*Result, error) {
	payload := map[string]any{
		"content":      req.Content,
		"content_type": req.ContentType,
		"hints":        req.Hints,
		"context":      req.Context,
	}
	if c.model != "" {
		payload["model"] = c.model
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("semantic: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("semantic: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return c.fallback(req, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return c.fallback(req, fmt.Errorf("semantic: backend returned %s: %s", resp.Status, strings.TrimSpace(string(respBody))))
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
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return c.fallback(req, fmt.Errorf("semantic: decode response: %w", err))
	}

	result := &Result{
		RiskScore:  clamp01(decoded.RiskScore),
		Confidence: clamp01(decoded.Confidence),
		Reasoning:  decoded.Reasoning,
		ModelUsed:  decoded.ModelUsed,
	}
	if result.ModelUsed == "" {
		result.ModelUsed = c.Name()
	}
	result.Labels = make([]Label, 0, len(decoded.Labels))
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

// ClassifyAsync implements Classifier.
func (c *HTTPClassifier) ClassifyAsync(ctx context.Context, req ClassifyRequest, cb func(*Result, error)) {
	go func() {
		result, err := c.Classify(ctx, req)
		cb(result, err)
	}()
}

func (c *HTTPClassifier) fallback(req ClassifyRequest, cause error) (*Result, error) {
	if !c.fallbackToStub {
		return nil, cause
	}
	result, err := c.stub.Classify(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("semantic: http backend failed (%v), stub fallback failed: %w", cause, err)
	}
	if result != nil {
		if result.Reasoning == "" {
			result.Reasoning = "http backend unavailable; stub fallback used"
		}
		if result.ModelUsed == "" || result.ModelUsed == "stub" {
			result.ModelUsed = "stub-fallback"
		}
	}
	return result, nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
