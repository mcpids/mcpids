package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	redisclient "github.com/mcpids/mcpids/internal/storage/redis"
	"github.com/mcpids/mcpids/pkg/types"
)

// Workflow manages the HITL approval lifecycle.
//
// Sequence:
//  1. Gateway calls Submit → creates Request, persists to Redis, notifies reviewers
//  2. Gateway calls WaitForDecision → blocks on Redis pub/sub channel
//  3. Admin calls Decide via REST API → publishes decision to channel
//  4. Gateway unblocks → forwards or rejects original MCP message
type Workflow interface {
	// Submit creates a new approval request and returns its ID.
	Submit(ctx context.Context, req *Request) (string, error)

	// WaitForDecision blocks until a decision is made or the context deadline is reached.
	// Returns ErrApprovalTimeout if the deadline expires before a decision.
	// Returns ErrApprovalDenied if the reviewer denied.
	WaitForDecision(ctx context.Context, requestID string) (*Decision, error)

	// Decide records a human decision and unblocks any waiting gateway goroutine.
	Decide(ctx context.Context, dec *Decision) error

	// Get retrieves a request by ID.
	Get(ctx context.Context, requestID string) (*Request, error)

	// ListPending returns all pending requests for a tenant.
	ListPending(ctx context.Context, tenantID string, limit, offset int) ([]*Request, error)
}

// workflowImpl is the default Workflow implementation backed by Redis pub/sub.
type workflowImpl struct {
	redis    *redisclient.Client
	notifier Notifier
	store    Store
	timeout  time.Duration
}

// NewWorkflow creates an approval workflow.
// redis is required for the pub/sub hold-and-wait mechanism.
// notifier may be nil (no notifications sent).
func NewWorkflow(redis *redisclient.Client, notifier Notifier, defaultTimeout time.Duration) Workflow {
	if defaultTimeout <= 0 {
		defaultTimeout = 5 * time.Minute
	}
	return &workflowImpl{
		redis:    redis,
		notifier: notifier,
		timeout:  defaultTimeout,
	}
}

// NewWorkflowWithStore creates an approval workflow with a persistent store.
// The store is used for ListPending and audit trail. redis is still required for pub/sub.
func NewWorkflowWithStore(redis *redisclient.Client, notifier Notifier, store Store, defaultTimeout time.Duration) Workflow {
	if defaultTimeout <= 0 {
		defaultTimeout = 5 * time.Minute
	}
	return &workflowImpl{
		redis:    redis,
		notifier: notifier,
		store:    store,
		timeout:  defaultTimeout,
	}
}

// Submit implements Workflow.
func (w *workflowImpl) Submit(ctx context.Context, req *Request) (string, error) {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.Status = StatusPending
	req.CreatedAt = time.Now().UTC()
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = req.CreatedAt.Add(w.timeout)
	}

	// Persist to Redis with TTL matching expiry.
	ttl := time.Until(req.ExpiresAt)
	if err := w.storeRequest(ctx, req, ttl); err != nil {
		return "", fmt.Errorf("approvals: persist: %w", err)
	}

	// Notify reviewers asynchronously (webhook, etc.).
	if w.notifier != nil {
		go func() {
			if err := w.notifier.Notify(context.Background(), req); err != nil {
				slog.Warn("approvals: notify failed", "request_id", req.ID, "error", err)
			}
		}()
	}

	// Persist to database if store is available.
	if w.store != nil {
		if err := w.store.SaveRequest(ctx, req); err != nil {
			slog.Warn("approvals: db persist failed", "request_id", req.ID, "error", err)
		}
	}

	slog.Info("approvals: created",
		"request_id", req.ID,
		"tenant_id", req.TenantID,
		"tool_name", req.ToolName,
		"expires_at", req.ExpiresAt)

	return req.ID, nil
}

// WaitForDecision implements Workflow.
// It subscribes to the Redis decision channel and blocks until a message arrives
// or the context deadline is reached.
func (w *workflowImpl) WaitForDecision(ctx context.Context, requestID string) (*Decision, error) {
	if w.redis == nil {
		return nil, fmt.Errorf("approvals: redis required for WaitForDecision")
	}

	channel := redisclient.ApprovalDecisionChannel(requestID)
	sub := w.redis.Subscribe(ctx, channel)
	defer func() {
		_ = sub.Close()
	}()

	// Check if already decided (race condition: decided before subscribe).
	req, err := w.Get(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req != nil && req.Status != StatusPending {
		return &Decision{
			RequestID: requestID,
			Status:    req.Status,
			DecidedBy: req.DecidedBy,
			Notes:     req.Notes,
		}, nil
	}

	ch := sub.Channel()
	select {
	case msg, ok := <-ch:
		if !ok {
			return nil, types.ErrApprovalTimeout
		}
		var dec Decision
		if err := json.Unmarshal([]byte(msg.Payload), &dec); err != nil {
			return nil, fmt.Errorf("approvals: decode decision: %w", err)
		}
		if dec.Status == StatusDenied {
			return &dec, types.ErrApprovalDenied
		}
		return &dec, nil

	case <-ctx.Done():
		return nil, types.ErrApprovalTimeout
	}
}

// Decide implements Workflow.
func (w *workflowImpl) Decide(ctx context.Context, dec *Decision) error {
	dec.Timestamp = time.Now().UTC()

	// Load and update the stored request.
	req, err := w.Get(ctx, dec.RequestID)
	if err != nil {
		return err
	}
	if req == nil {
		return types.ErrApprovalNotFound
	}
	if req.Status != StatusPending {
		return fmt.Errorf("approvals: request %s is already %s", dec.RequestID, req.Status)
	}

	req.Status = dec.Status
	req.DecidedBy = dec.DecidedBy
	req.DecidedAt = &dec.Timestamp
	req.Notes = dec.Notes

	if err := w.storeRequest(ctx, req, 1*time.Hour); err != nil {
		return fmt.Errorf("approvals: update: %w", err)
	}

	// Publish decision to the waiting gateway goroutine.
	if w.redis != nil {
		payload, _ := json.Marshal(dec)
		channel := redisclient.ApprovalDecisionChannel(dec.RequestID)
		if err := w.redis.Publish(ctx, channel, payload); err != nil {
			slog.Warn("approvals: publish decision failed", "request_id", dec.RequestID, "error", err)
		}
	}

	// Persist decision to database if store is available.
	if w.store != nil {
		if err := w.store.UpdateDecision(ctx, dec); err != nil {
			slog.Warn("approvals: db decision persist failed", "request_id", dec.RequestID, "error", err)
		}
	}

	slog.Info("approvals: decided",
		"request_id", dec.RequestID,
		"status", dec.Status,
		"decided_by", dec.DecidedBy)

	return nil
}

// Get implements Workflow.
func (w *workflowImpl) Get(ctx context.Context, requestID string) (*Request, error) {
	if w.redis == nil {
		return nil, nil
	}

	data, err := w.redis.GetJSON(ctx, redisclient.ApprovalKey(requestID))
	if err != nil {
		return nil, fmt.Errorf("approvals: get %s: %w", requestID, err)
	}
	if data == nil {
		return nil, nil
	}

	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("approvals: unmarshal: %w", err)
	}

	// Auto-expire stale pending requests.
	if req.Status == StatusPending && time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		_ = w.storeRequest(ctx, &req, 1*time.Hour)
	}

	return &req, nil
}

// ListPending implements Workflow.
// When a Store is configured, queries the database. Falls back to returning nil otherwise.
func (w *workflowImpl) ListPending(ctx context.Context, tenantID string, limit, offset int) ([]*Request, error) {
	if w.store != nil {
		return w.store.ListPending(ctx, tenantID, limit, offset)
	}
	// No persistent store - Redis doesn't support server-side pattern scanning for this.
	return nil, nil
}

func (w *workflowImpl) storeRequest(ctx context.Context, req *Request, ttl time.Duration) error {
	if w.redis == nil {
		return nil
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return w.redis.SetJSON(ctx, redisclient.ApprovalKey(req.ID), data, ttl)
}
