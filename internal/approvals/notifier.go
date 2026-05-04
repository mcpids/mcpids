package approvals

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier dispatches approval request notifications to configured channels.
type Notifier interface {
	// Notify sends a notification for the given approval request.
	Notify(ctx context.Context, req *Request) error
}

// WebhookNotifier sends approval requests to an HTTP webhook endpoint.
// The payload is signed with HMAC-SHA256 using the configured secret.
type WebhookNotifier struct {
	URL    string
	Secret string
	client *http.Client
}

// NewWebhookNotifier creates a webhook notifier.
func NewWebhookNotifier(url, secret string) *WebhookNotifier {
	return &WebhookNotifier{
		URL:    url,
		Secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify implements Notifier.
func (n *WebhookNotifier) Notify(ctx context.Context, req *Request) error {
	if n.URL == "" {
		return nil
	}

	payload := map[string]any{
		"request_id": req.ID,
		"tenant_id":  req.TenantID,
		"tool_name":  req.ToolName,
		"server_id":  req.ServerID,
		"verdict":    req.Verdict,
		"created_at": req.CreatedAt,
		"expires_at": req.ExpiresAt,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "mcpids-approvals/1.0")

	if n.Secret != "" {
		sig := computeHMAC(body, n.Secret)
		httpReq.Header.Set("X-MCPIDS-Signature", "sha256="+sig)
	}

	resp, err := n.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("webhook: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: server returned %d", resp.StatusCode)
	}

	return nil
}

func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// NoOpNotifier is a notifier that does nothing. Used in tests and dev mode.
type NoOpNotifier struct{}

func (n *NoOpNotifier) Notify(_ context.Context, _ *Request) error { return nil }
