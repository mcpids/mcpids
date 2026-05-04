// Package events persists call, detection, and audit records.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcpids/mcpids/pkg/types"
)

// Recorder stores forensic and audit records.
type Recorder interface {
	RecordCall(ctx context.Context, rec CallRecord) (string, error)
	RecordDetection(ctx context.Context, rec DetectionRecord) (string, error)
	RecordAudit(ctx context.Context, rec AuditRecord) error
}

// CallRecord is one intercepted MCP message persisted to calls.
type CallRecord struct {
	ID              string
	SessionID       string
	TenantID        string
	AgentID         string
	ServerID        string
	Method          string
	ToolName        string
	RequestPayload  json.RawMessage
	ResponsePayload json.RawMessage
	Verdict         *types.Verdict
	DurationMS      int
	CalledAt        time.Time
}

// DetectionRecord is one non-allow verdict persisted to detections.
type DetectionRecord struct {
	CallID    string
	SessionID string
	TenantID  string
	ServerID  string
	Verdict   *types.Verdict
	Evidence  map[string]any
	CreatedAt time.Time
}

// AuditRecord is one immutable control-plane audit entry.
type AuditRecord struct {
	TenantID     string
	ActorID      string
	ActorKind    string
	Action       string
	ResourceKind string
	ResourceID   string
	Payload      map[string]any
	IPAddress    string
}

// PGRecorder persists event records to PostgreSQL.
type PGRecorder struct {
	pool *pgxpool.Pool
}

// NewPGRecorder creates a PostgreSQL-backed recorder.
func NewPGRecorder(pool *pgxpool.Pool) *PGRecorder {
	return &PGRecorder{pool: pool}
}

// RecordCall implements Recorder.
func (r *PGRecorder) RecordCall(ctx context.Context, rec CallRecord) (string, error) {
	if rec.TenantID == "" || rec.SessionID == "" || rec.Method == "" {
		return "", nil
	}
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.CalledAt.IsZero() {
		rec.CalledAt = time.Now().UTC()
	}

	verdictJSON, err := json.Marshal(rec.Verdict)
	if err != nil {
		return "", fmt.Errorf("events: marshal call verdict: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO calls (
			 id, session_id, tenant_id, server_id, method, tool_name,
			 request_payload, response_payload, verdict, duration_ms, called_at
		 )
		 VALUES (
			 $1, $2, $3, NULLIF($4, '')::uuid, $5, NULLIF($6, ''),
			 $7::jsonb, $8::jsonb, $9::jsonb, $10, $11
		 )`,
		rec.ID,
		rec.SessionID,
		rec.TenantID,
		rec.ServerID,
		rec.Method,
		rec.ToolName,
		nullableJSON(rec.RequestPayload),
		nullableJSON(rec.ResponsePayload),
		string(verdictJSON),
		rec.DurationMS,
		rec.CalledAt,
	)
	if err != nil {
		return "", fmt.Errorf("events: insert call: %w", err)
	}
	return rec.ID, nil
}

// RecordDetection implements Recorder.
func (r *PGRecorder) RecordDetection(ctx context.Context, rec DetectionRecord) (string, error) {
	if rec.Verdict == nil || rec.Verdict.Decision == types.DecisionAllow || rec.TenantID == "" {
		return "", nil
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	ruleIDs := rec.Verdict.MatchedRules
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	semanticLabels := rec.Verdict.SemanticLabels
	if semanticLabels == nil {
		semanticLabels = []string{}
	}

	evidenceJSON, err := json.Marshal(rec.Evidence)
	if err != nil {
		return "", fmt.Errorf("events: marshal evidence: %w", err)
	}

	var id string
	err = r.pool.QueryRow(ctx,
		`INSERT INTO detections (
			 call_id, session_id, tenant_id, server_id, rule_ids,
			 semantic_labels, risk_score, severity, decision, evidence, created_at
		 )
		 VALUES (
			 NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, $3, NULLIF($4, '')::uuid,
			 $5, $6, $7, $8, $9, $10::jsonb, $11
		 )
		 RETURNING id`,
		rec.CallID,
		rec.SessionID,
		rec.TenantID,
		rec.ServerID,
		ruleIDs,
		semanticLabels,
		rec.Verdict.RiskScore,
		rec.Verdict.Severity,
		rec.Verdict.Decision,
		string(evidenceJSON),
		rec.CreatedAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("events: insert detection: %w", err)
	}
	return id, nil
}

// RecordAudit implements Recorder.
func (r *PGRecorder) RecordAudit(ctx context.Context, rec AuditRecord) error {
	if rec.TenantID == "" || rec.Action == "" {
		return nil
	}
	if rec.ActorKind == "" {
		rec.ActorKind = "system"
	}
	if rec.ActorID != "" {
		if _, err := uuid.Parse(rec.ActorID); err != nil {
			rec.ActorID = ""
		}
	}
	if rec.ResourceID != "" {
		if _, err := uuid.Parse(rec.ResourceID); err != nil {
			rec.ResourceID = ""
		}
	}

	payloadJSON, err := json.Marshal(rec.Payload)
	if err != nil {
		return fmt.Errorf("events: marshal audit payload: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_events (
			 tenant_id, actor_id, actor_kind, action,
			 resource_kind, resource_id, payload, ip_address
		 )
		 VALUES (
			 $1, NULLIF($2, '')::uuid, $3, $4,
			 NULLIF($5, ''), NULLIF($6, '')::uuid, $7::jsonb,
			 NULLIF($8, '')::inet
		 )`,
		rec.TenantID,
		rec.ActorID,
		rec.ActorKind,
		rec.Action,
		rec.ResourceKind,
		rec.ResourceID,
		string(payloadJSON),
		rec.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("events: insert audit: %w", err)
	}
	return nil
}

func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}
