package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcpids/mcpids/internal/mcp"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

// Store persists MCP session lifecycle state.
type Store interface {
	Save(ctx context.Context, sess *mcp.Session) error
	Load(ctx context.Context, sessionID string) (*mcp.Session, error)
	LoadByExternalID(ctx context.Context, externalID string) (*mcp.Session, error)
}

// PGStore persists sessions in PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PostgreSQL-backed session store.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// Save upserts the session row.
func (s *PGStore) Save(ctx context.Context, sess *mcp.Session) error {
	if sess == nil || sess.ID == "" || sess.TenantID == "" || sess.AgentID == "" {
		return nil
	}
	externalID := sess.ExternalID
	if externalID == "" {
		externalID = sess.ID
	}

	metadata, err := json.Marshal(map[string]any{
		"server_capabilities": sess.NegotiatedCapabilities,
	})
	if err != nil {
		return fmt.Errorf("session store: marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO sessions (
			 id, tenant_id, agent_id, mcp_server_id, external_id,
			 protocol_version, client_name, client_version,
			 server_name, server_version, transport, state,
			 quarantine_reason, quarantined_at, started_at, ended_at,
			 metadata
		 )
		 VALUES (
			 $1, $2, $3, NULLIF($4, '')::uuid, $5,
			 $6, $7, $8,
			 $9, $10, $11, $12,
			 $13, $14, $15, $16,
			 $17::jsonb
		 )
		 ON CONFLICT (id) DO UPDATE SET
			 mcp_server_id = EXCLUDED.mcp_server_id,
			 protocol_version = EXCLUDED.protocol_version,
			 client_name = EXCLUDED.client_name,
			 client_version = EXCLUDED.client_version,
			 server_name = EXCLUDED.server_name,
			 server_version = EXCLUDED.server_version,
			 transport = EXCLUDED.transport,
			 state = EXCLUDED.state,
			 quarantine_reason = EXCLUDED.quarantine_reason,
			 quarantined_at = EXCLUDED.quarantined_at,
			 ended_at = EXCLUDED.ended_at,
			 metadata = EXCLUDED.metadata`,
		sess.ID,
		sess.TenantID,
		sess.AgentID,
		sess.ServerID,
		externalID,
		defaultProtocolVersion(sess.ProtocolVersion),
		emptyToNil(sess.ClientInfo.Name),
		emptyToNil(sess.ClientInfo.Version),
		emptyToNil(sess.ServerInfo.Name),
		emptyToNil(sess.ServerInfo.Version),
		defaultTransport(sess.Transport),
		sess.State.String(),
		emptyToNil(sess.QuarantineReason),
		sess.QuarantinedAt,
		zeroTimeToNow(sess.StartedAt),
		sess.EndedAt,
		string(metadata),
	)
	if err != nil {
		return fmt.Errorf("session store: save %s: %w", sess.ID, err)
	}
	return nil
}

// Load fetches a session by internal session ID.
func (s *PGStore) Load(ctx context.Context, sessionID string) (*mcp.Session, error) {
	return s.loadByQuery(ctx,
		`SELECT id::text, external_id, tenant_id::text, agent_id::text,
			 COALESCE(mcp_server_id::text, ''), transport, state,
			 protocol_version, COALESCE(client_name, ''), COALESCE(client_version, ''),
			 COALESCE(server_name, ''), COALESCE(server_version, ''),
			 COALESCE(quarantine_reason, ''), quarantined_at, started_at,
			 COALESCE(ended_at, started_at)
		 FROM sessions WHERE id = $1`,
		sessionID,
	)
}

// LoadByExternalID fetches a session by MCP external session ID.
func (s *PGStore) LoadByExternalID(ctx context.Context, externalID string) (*mcp.Session, error) {
	return s.loadByQuery(ctx,
		`SELECT id::text, external_id, tenant_id::text, agent_id::text,
			 COALESCE(mcp_server_id::text, ''), transport, state,
			 protocol_version, COALESCE(client_name, ''), COALESCE(client_version, ''),
			 COALESCE(server_name, ''), COALESCE(server_version, ''),
			 COALESCE(quarantine_reason, ''), quarantined_at, started_at,
			 COALESCE(ended_at, started_at)
		 FROM sessions WHERE external_id = $1 ORDER BY started_at DESC LIMIT 1`,
		externalID,
	)
}

func (s *PGStore) loadByQuery(ctx context.Context, query string, arg any) (*mcp.Session, error) {
	var sess mcp.Session
	var state string
	var quarantinedAt *time.Time
	var endedAt time.Time

	err := s.pool.QueryRow(ctx, query, arg).Scan(
		&sess.ID,
		&sess.ExternalID,
		&sess.TenantID,
		&sess.AgentID,
		&sess.ServerID,
		&sess.Transport,
		&state,
		&sess.ProtocolVersion,
		&sess.ClientInfo.Name,
		&sess.ClientInfo.Version,
		&sess.ServerInfo.Name,
		&sess.ServerInfo.Version,
		&sess.QuarantineReason,
		&quarantinedAt,
		&sess.StartedAt,
		&endedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("session store: load: %w", err)
	}

	sess.State = parseSessionState(state)
	sess.QuarantinedAt = quarantinedAt
	if sess.State == mcp.StateClosed || sess.State == mcp.StateError || sess.State == mcp.StateQuarantined {
		sess.EndedAt = &endedAt
	}
	sess.LastSeenAt = endedAt
	return &sess, nil
}

func parseSessionState(state string) mcp.SessionState {
	switch state {
	case "initializing":
		return mcp.StateInitializing
	case "ready":
		return mcp.StateReady
	case "quarantined":
		return mcp.StateQuarantined
	case "closed":
		return mcp.StateClosed
	case "error":
		return mcp.StateError
	default:
		return mcp.StateNew
	}
}

func defaultProtocolVersion(v string) string {
	if v == "" {
		return mcp.ProtocolVersion
	}
	return v
}

func defaultTransport(v string) string {
	if v == "" {
		return string("http")
	}
	return v
}

func emptyToNil(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func zeroTimeToNow(v time.Time) time.Time {
	if v.IsZero() {
		return time.Now().UTC()
	}
	return v
}

// GRPCStore publishes session lifecycle changes to the control-plane EventService.
type GRPCStore struct {
	client mcpidsv1.EventServiceClient
}

// NewGRPCStore creates a service-plane session store.
func NewGRPCStore(client mcpidsv1.EventServiceClient) *GRPCStore {
	return &GRPCStore{client: client}
}

// Save implements Store by publishing a session lifecycle event.
func (s *GRPCStore) Save(ctx context.Context, sess *mcp.Session) error {
	if s == nil || s.client == nil || sess == nil || sess.ID == "" || sess.TenantID == "" {
		return nil
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session grpc store: marshal session: %w", err)
	}
	_, err = s.client.PublishEvent(ctx, &mcpidsv1.Event{
		EventId:     uuid.New().String(),
		Kind:        sessionEventKind(sess.State),
		TenantId:    sess.TenantID,
		AgentId:     sess.AgentID,
		SessionId:   sess.ID,
		ServerId:    sess.ServerID,
		Timestamp:   zeroTimeToNow(sess.LastSeenAt).UnixMilli(),
		PayloadJson: payload,
	})
	if err != nil {
		return fmt.Errorf("session grpc store: publish session event: %w", err)
	}
	return nil
}

// Load is not supported over EventService.
func (s *GRPCStore) Load(context.Context, string) (*mcp.Session, error) {
	return nil, nil
}

// LoadByExternalID is not supported over EventService.
func (s *GRPCStore) LoadByExternalID(context.Context, string) (*mcp.Session, error) {
	return nil, nil
}

func sessionEventKind(state mcp.SessionState) mcpidsv1.EventKind {
	switch state {
	case mcp.StateQuarantined:
		return mcpidsv1.EventKind_EVENT_KIND_SESSION_QUARANTINED
	case mcp.StateClosed, mcp.StateError:
		return mcpidsv1.EventKind_EVENT_KIND_SESSION_ENDED
	default:
		return mcpidsv1.EventKind_EVENT_KIND_SESSION_STARTED
	}
}
