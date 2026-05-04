package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists graph nodes/edges and can answer graph queries after process restarts.
type Store interface {
	RecordCall(ctx context.Context, rec CallRecord, previousToolKey string) error
	RecordResourceAccess(ctx context.Context, rec ResourceAccessRecord) error
	Analyze(ctx context.Context, tenantID, sessionID string) (*Signal, error)
	GetSessionGraph(ctx context.Context, sessionID string) ([]Node, []Edge, error)
	GetAgentGraph(ctx context.Context, agentID string, since time.Time) ([]Node, []Edge, error)
}

// PGStore persists graph state in PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PostgreSQL graph store.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// RecordCall persists one observed tool call and its graph edges.
func (s *PGStore) RecordCall(ctx context.Context, rec CallRecord, previousToolKey string) error {
	if s == nil || s.pool == nil {
		return nil
	}
	now := rec.CalledAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("graph store: begin call tx: %w", err)
	}
	defer tx.Rollback(ctx)

	agentNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindAgent), rec.AgentID, rec.AgentID, now, 0)
	if err != nil {
		return err
	}
	sessionNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindSession), rec.SessionID, rec.SessionID, now, 0)
	if err != nil {
		return err
	}
	serverNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindServer), rec.ServerID, rec.ServerID, now, 0)
	if err != nil {
		return err
	}
	toolKey := rec.ServerID + ":" + rec.ToolName
	toolNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindTool), toolKey, rec.ToolName, now, 1)
	if err != nil {
		return err
	}

	if err := insertGraphEdge(ctx, tx, rec.TenantID, agentNodeID, serverNodeID, string(EdgeKindConnectsTo), rec.SessionID, now); err != nil {
		return err
	}
	if err := insertGraphEdge(ctx, tx, rec.TenantID, sessionNodeID, serverNodeID, string(EdgeKindBelongsTo), rec.SessionID, now); err != nil {
		return err
	}
	if err := insertGraphEdge(ctx, tx, rec.TenantID, sessionNodeID, toolNodeID, string(EdgeKindCalls), rec.SessionID, now); err != nil {
		return err
	}
	if previousToolKey != "" {
		prevToolNodeID, err := lookupGraphNodeID(ctx, tx, rec.TenantID, string(NodeKindTool), previousToolKey)
		if err == nil && prevToolNodeID != "" {
			if err := insertGraphEdge(ctx, tx, rec.TenantID, prevToolNodeID, toolNodeID, string(EdgeKindOutputFlowsTo), rec.SessionID, now); err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

// RecordResourceAccess persists one resource access edge.
func (s *PGStore) RecordResourceAccess(ctx context.Context, rec ResourceAccessRecord) error {
	if s == nil || s.pool == nil {
		return nil
	}
	now := rec.AccessedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("graph store: begin resource tx: %w", err)
	}
	defer tx.Rollback(ctx)

	agentNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindAgent), rec.AgentID, rec.AgentID, now, 0)
	if err != nil {
		return err
	}
	sessionNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindSession), rec.SessionID, rec.SessionID, now, 0)
	if err != nil {
		return err
	}
	serverNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindServer), rec.ServerID, rec.ServerID, now, 0)
	if err != nil {
		return err
	}
	resourceNodeID, err := upsertGraphNode(ctx, tx, rec.TenantID, string(NodeKindResource), rec.ResourceURI, rec.ResourceURI, now, 0)
	if err != nil {
		return err
	}

	if err := insertGraphEdge(ctx, tx, rec.TenantID, agentNodeID, serverNodeID, string(EdgeKindConnectsTo), rec.SessionID, now); err != nil {
		return err
	}
	if err := insertGraphEdge(ctx, tx, rec.TenantID, sessionNodeID, resourceNodeID, string(EdgeKindAccesses), rec.SessionID, now); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Analyze computes a graph risk signal from persisted edges.
func (s *PGStore) Analyze(ctx context.Context, tenantID, sessionID string) (*Signal, error) {
	if s == nil || s.pool == nil {
		return &Signal{}, nil
	}
	sig := &Signal{}
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT gn_to.label)
		 FROM graph_edges ge
		 JOIN graph_nodes gn_to ON gn_to.id = ge.to_id
		 WHERE ge.session_id = $1 AND ge.tenant_id = $2 AND ge.kind = $3`,
		sessionID, tenantID, string(EdgeKindBelongsTo),
	).Scan(&sig.UniqueServerCount); err != nil {
		return nil, fmt.Errorf("graph store: count servers: %w", err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM graph_edges
		 WHERE session_id = $1 AND tenant_id = $2 AND kind = $3`,
		sessionID, tenantID, string(EdgeKindCalls),
	).Scan(&sig.ChainDepth); err != nil {
		return nil, fmt.Errorf("graph store: count chain depth: %w", err)
	}
	if sig.UniqueServerCount > 1 {
		sig.LateralMovement = true
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("session accessed %d distinct servers", sig.UniqueServerCount))
	}
	var score float64
	if sig.LateralMovement {
		score += 0.3 * float64(sig.UniqueServerCount-1)
	}
	if sig.ChainDepth > 5 {
		score += 0.2 * float64(sig.ChainDepth-5) / 10.0
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("deep tool call chain (depth=%d)", sig.ChainDepth))
	}
	if score > 1 {
		score = 1
	}
	sig.RiskContribution = score
	return sig, nil
}

// GetSessionGraph loads the persisted graph for one session.
func (s *PGStore) GetSessionGraph(ctx context.Context, sessionID string) ([]Node, []Edge, error) {
	if s == nil || s.pool == nil {
		return nil, nil, nil
	}
	return s.queryGraph(ctx,
		`SELECT ge.id::text, ge.tenant_id::text,
		        gn_from.label, COALESCE(gn_from.attrs->>'display_label', gn_from.label), gn_from.kind,
		        gn_to.label, COALESCE(gn_to.attrs->>'display_label', gn_to.label), gn_to.kind,
		        ge.kind, ge.weight, COALESCE(ge.session_id::text, ''), ge.created_at,
		        gn_from.first_seen_at, COALESCE(gn_from.last_seen_at, gn_from.first_seen_at), COALESCE(gn_from.call_count, 0),
		        gn_to.first_seen_at, COALESCE(gn_to.last_seen_at, gn_to.first_seen_at), COALESCE(gn_to.call_count, 0)
		   FROM graph_edges ge
		   JOIN graph_nodes gn_from ON gn_from.id = ge.from_id
		   JOIN graph_nodes gn_to ON gn_to.id = ge.to_id
		  WHERE ge.session_id = $1
		  ORDER BY ge.created_at ASC`,
		sessionID,
	)
}

// GetAgentGraph loads the persisted graph around one agent.
func (s *PGStore) GetAgentGraph(ctx context.Context, agentID string, since time.Time) ([]Node, []Edge, error) {
	if s == nil || s.pool == nil {
		return nil, nil, nil
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	return s.queryGraph(ctx,
		`SELECT ge.id::text, ge.tenant_id::text,
		        gn_from.label, COALESCE(gn_from.attrs->>'display_label', gn_from.label), gn_from.kind,
		        gn_to.label, COALESCE(gn_to.attrs->>'display_label', gn_to.label), gn_to.kind,
		        ge.kind, ge.weight, COALESCE(ge.session_id::text, ''), ge.created_at,
		        gn_from.first_seen_at, COALESCE(gn_from.last_seen_at, gn_from.first_seen_at), COALESCE(gn_from.call_count, 0),
		        gn_to.first_seen_at, COALESCE(gn_to.last_seen_at, gn_to.first_seen_at), COALESCE(gn_to.call_count, 0)
		   FROM graph_edges ge
		   JOIN graph_nodes gn_from ON gn_from.id = ge.from_id
		   JOIN graph_nodes gn_to ON gn_to.id = ge.to_id
		  WHERE ge.created_at >= $2
		    AND (
		      (gn_from.kind = 'agent' AND gn_from.label = $1)
		      OR (gn_to.kind = 'agent' AND gn_to.label = $1)
		      OR ge.session_id IN (
		            SELECT session_id
		              FROM graph_edges ge2
		              JOIN graph_nodes gna ON gna.id = ge2.from_id
		             WHERE gna.kind = 'agent' AND gna.label = $1
		      )
		    )
		  ORDER BY ge.created_at ASC`,
		agentID, since.UTC(),
	)
}

func (s *PGStore) queryGraph(ctx context.Context, query string, args ...any) ([]Node, []Edge, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("graph store: query graph: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	var edges []Edge
	for rows.Next() {
		var edge Edge
		var fromID, fromLabel, fromKind string
		var toID, toLabel, toKind string
		var fromFirstSeen, fromLastSeen, toFirstSeen, toLastSeen time.Time
		var fromCallCount, toCallCount int
		if err := rows.Scan(
			&edge.ID,
			&edge.TenantID,
			&fromID,
			&fromLabel,
			&fromKind,
			&toID,
			&toLabel,
			&toKind,
			&edge.Kind,
			&edge.Weight,
			&edge.SessionID,
			&edge.CreatedAt,
			&fromFirstSeen,
			&fromLastSeen,
			&fromCallCount,
			&toFirstSeen,
			&toLastSeen,
			&toCallCount,
		); err != nil {
			return nil, nil, fmt.Errorf("graph store: scan graph edge: %w", err)
		}
		edge.FromID = fromID
		edge.ToID = toID
		edges = append(edges, edge)
		nodes = append(nodes,
			Node{ID: fromID, TenantID: edge.TenantID, Kind: NodeKind(fromKind), Label: fromLabel, FirstSeen: fromFirstSeen, LastSeen: fromLastSeen, CallCount: fromCallCount},
			Node{ID: toID, TenantID: edge.TenantID, Kind: NodeKind(toKind), Label: toLabel, FirstSeen: toFirstSeen, LastSeen: toLastSeen, CallCount: toCallCount},
		)
	}
	if rows.Err() != nil {
		return nil, nil, fmt.Errorf("graph store: iterate graph rows: %w", rows.Err())
	}
	return deduplicateNodes(nodes), edges, nil
}

func upsertGraphNode(ctx context.Context, tx pgx.Tx, tenantID, kind, logicalID, displayLabel string, ts time.Time, callDelta int) (string, error) {
	attrsJSON, err := json.Marshal(map[string]string{
		"logical_id":    logicalID,
		"display_label": displayLabel,
	})
	if err != nil {
		return "", fmt.Errorf("graph store: marshal node attrs: %w", err)
	}
	var nodeID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO graph_nodes (tenant_id, kind, label, attrs, first_seen_at, last_seen_at, call_count)
		 VALUES ($1, $2, $3, $4::jsonb, $5, $5, $6)
		 ON CONFLICT (tenant_id, kind, label) DO UPDATE SET
		   attrs = graph_nodes.attrs || EXCLUDED.attrs,
		   last_seen_at = GREATEST(graph_nodes.last_seen_at, EXCLUDED.last_seen_at),
		   call_count = graph_nodes.call_count + EXCLUDED.call_count
		 RETURNING id::text`,
		tenantID, kind, logicalID, string(attrsJSON), ts.UTC(), callDelta,
	).Scan(&nodeID); err != nil {
		return "", fmt.Errorf("graph store: upsert %s node %s: %w", kind, logicalID, err)
	}
	return nodeID, nil
}

func lookupGraphNodeID(ctx context.Context, tx pgx.Tx, tenantID, kind, logicalID string) (string, error) {
	var nodeID string
	if err := tx.QueryRow(ctx,
		`SELECT id::text FROM graph_nodes WHERE tenant_id = $1 AND kind = $2 AND label = $3`,
		tenantID, kind, logicalID,
	).Scan(&nodeID); err != nil {
		return "", err
	}
	return nodeID, nil
}

func insertGraphEdge(ctx context.Context, tx pgx.Tx, tenantID, fromID, toID, kind, sessionID string, ts time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO graph_edges (tenant_id, from_id, to_id, kind, weight, session_id, created_at)
		 VALUES ($1, $2, $3, $4, 1.0, NULLIF($5, '')::uuid, $6)`,
		tenantID, fromID, toID, kind, sessionID, ts.UTC(),
	)
	if err != nil {
		return fmt.Errorf("graph store: insert edge %s %s->%s: %w", kind, fromID, toID, err)
	}
	return nil
}
