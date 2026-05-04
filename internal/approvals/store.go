package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcpids/mcpids/pkg/types"
)

// Store abstracts approval persistence. The default workflow uses Redis for
// real-time pub/sub and an optional Store for durable queries like ListPending.
type Store interface {
	// SaveRequest persists an approval request to the database.
	SaveRequest(ctx context.Context, req *Request) error

	// UpdateDecision records a decision in the database.
	UpdateDecision(ctx context.Context, dec *Decision) error

	// ListPending returns all pending requests for a tenant with pagination.
	ListPending(ctx context.Context, tenantID string, limit, offset int) ([]*Request, error)
}

// ─── PostgreSQL store ───────────────────────────────────────────────────────

// PGStore persists approvals to the approvals table.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PostgreSQL-backed approval store.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// SaveRequest inserts an approval request into the database.
func (s *PGStore) SaveRequest(ctx context.Context, req *Request) error {
	verdictJSON, err := json.Marshal(req.Verdict)
	if err != nil {
		return fmt.Errorf("approvals store: marshal verdict: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO approvals (id, tenant_id, session_id, server_id, agent_id, tool_name, raw_payload, verdict, status, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (id) DO UPDATE SET status = $9`,
		req.ID, req.TenantID, nullableUUID(req.SessionID), nullableUUID(req.ServerID),
		nullableUUID(req.AgentID), req.ToolName, req.RawPayload,
		verdictJSON, string(req.Status), req.ExpiresAt, req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("approvals store: save request: %w", err)
	}
	return nil
}

// UpdateDecision records a decision in the database.
func (s *PGStore) UpdateDecision(ctx context.Context, dec *Decision) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE approvals SET status = $1, decided_at = $2, notes = $3 WHERE id = $4`,
		string(dec.Status), dec.Timestamp, dec.Notes, dec.RequestID,
	)
	if err != nil {
		return fmt.Errorf("approvals store: update decision: %w", err)
	}
	return nil
}

// ListPending returns pending approvals for a tenant from the database.
func (s *PGStore) ListPending(ctx context.Context, tenantID string, limit, offset int) ([]*Request, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, tenant_id, agent_id, session_id, server_id, tool_name, status, created_at, expires_at, notes
		 FROM approvals WHERE status = 'pending'`
	args := []any{}

	if tenantID != "" {
		query += " AND tenant_id = $1"
		args = append(args, tenantID)
	}

	query += fmt.Sprintf(" ORDER BY created_at ASC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("approvals store: list pending: %w", err)
	}
	defer rows.Close()

	var results []*Request
	for rows.Next() {
		var r Request
		var agentID, sessionID, serverID, notes *string
		if err := rows.Scan(&r.ID, &r.TenantID, &agentID, &sessionID, &serverID, &r.ToolName, &r.Status, &r.CreatedAt, &r.ExpiresAt, &notes); err != nil {
			continue
		}
		if agentID != nil {
			r.AgentID = *agentID
		}
		if sessionID != nil {
			r.SessionID = *sessionID
		}
		if serverID != nil {
			r.ServerID = *serverID
		}
		if notes != nil {
			r.Notes = *notes
		}

		// Auto-expire stale pending requests.
		if r.Status == StatusPending && time.Now().After(r.ExpiresAt) {
			r.Status = StatusExpired
			_, _ = s.pool.Exec(ctx, "UPDATE approvals SET status = 'expired' WHERE id = $1", r.ID)
			continue // skip expired ones
		}

		results = append(results, &r)
	}
	return results, nil
}

// nullableUUID returns nil for empty strings (to insert NULL into UUID columns).
func nullableUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ─── Verdict type alias for JSON serialization ─────────────────────────────
// (types.Verdict already has JSON tags, just used here for clarity)
var _ = types.Verdict{}
