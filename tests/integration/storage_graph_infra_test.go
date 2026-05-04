//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mcpids/mcpids/internal/graph"
	postgresdb "github.com/mcpids/mcpids/internal/storage/postgres"
	redisdb "github.com/mcpids/mcpids/internal/storage/redis"
)

func TestPostgresGraphAndRedisRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("MCPIDS_TEST_DATABASE_URL")
	redisURL := os.Getenv("MCPIDS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("set MCPIDS_TEST_DATABASE_URL and MCPIDS_TEST_REDIS_URL to run infra smoke test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := postgresdb.NewDB(ctx, postgresdb.DefaultConfig(databaseURL))
	if err != nil {
		t.Fatalf("postgresdb.NewDB: %v", err)
	}
	defer db.Close()

	rdb, err := redisdb.NewClient(ctx, redisdb.DefaultConfig(redisURL))
	if err != nil {
		t.Fatalf("redisdb.NewClient: %v", err)
	}
	defer rdb.Close()

	tenantID := uuid.NewString()
	agentID := uuid.NewString()
	serverAID := uuid.NewString()
	serverBID := uuid.NewString()
	sessionID := uuid.NewString()

	seedGraphFixtures(t, ctx, db, tenantID, agentID, serverAID, serverBID, sessionID)

	engine := graph.NewEngineWithStore(graph.NewPGStore(db.Pool()))
	firstCallAt := time.Now().UTC()
	if err := engine.RecordCall(ctx, graph.CallRecord{
		TenantID:  tenantID,
		AgentID:   agentID,
		SessionID: sessionID,
		ServerID:  serverAID,
		ToolName:  "read_file",
		CalledAt:  firstCallAt,
	}); err != nil {
		t.Fatalf("RecordCall serverA: %v", err)
	}
	if err := engine.RecordCall(ctx, graph.CallRecord{
		TenantID:  tenantID,
		AgentID:   agentID,
		SessionID: sessionID,
		ServerID:  serverBID,
		ToolName:  "write_file",
		CalledAt:  firstCallAt.Add(time.Second),
	}); err != nil {
		t.Fatalf("RecordCall serverB: %v", err)
	}

	signal, err := engine.Analyze(ctx, tenantID, sessionID)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if signal.UniqueServerCount != 2 || !signal.LateralMovement {
		t.Fatalf("expected lateral movement across 2 servers, got %+v", signal)
	}

	sessionNodes, sessionEdges, err := engine.GetSessionGraph(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSessionGraph: %v", err)
	}
	if len(sessionNodes) == 0 || len(sessionEdges) == 0 {
		t.Fatalf("expected persisted session graph, got nodes=%d edges=%d", len(sessionNodes), len(sessionEdges))
	}

	agentNodes, agentEdges, err := engine.GetAgentGraph(ctx, agentID, firstCallAt.Add(-time.Minute))
	if err != nil {
		t.Fatalf("GetAgentGraph: %v", err)
	}
	if len(agentNodes) == 0 || len(agentEdges) == 0 {
		t.Fatalf("expected persisted agent graph, got nodes=%d edges=%d", len(agentNodes), len(agentEdges))
	}

	const cacheKey = "integration:graph:test"
	payload := []byte(`{"ok":true}`)
	if err := rdb.SetJSON(ctx, cacheKey, payload, time.Minute); err != nil {
		t.Fatalf("SetJSON: %v", err)
	}
	gotPayload, err := rdb.GetJSON(ctx, cacheKey)
	if err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("unexpected Redis payload %q", string(gotPayload))
	}

	const channel = "integration:graph:pubsub"
	sub := rdb.Subscribe(ctx, channel)
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatalf("Subscribe.Receive: %v", err)
	}
	if err := rdb.Publish(ctx, channel, []byte("ready")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	msg, err := sub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("ReceiveMessage: %v", err)
	}
	if msg.Payload != "ready" {
		t.Fatalf("unexpected pubsub payload %q", msg.Payload)
	}
}

func seedGraphFixtures(t *testing.T, ctx context.Context, db *postgresdb.DB, tenantID, agentID, serverAID, serverBID, sessionID string) {
	t.Helper()

	statements := []struct {
		query string
		args  []any
	}{
		{
			query: `INSERT INTO tenants (id, name, slug, plan) VALUES ($1, $2, $3, 'enterprise')`,
			args:  []any{tenantID, "Integration Tenant", "integration-" + tenantID[:8]},
		},
		{
			query: `INSERT INTO agents (id, tenant_id, name, kind, status, last_seen_at) VALUES ($1, $2, 'integration-agent', 'gateway', 'online', NOW())`,
			args:  []any{agentID, tenantID},
		},
		{
			query: `INSERT INTO mcp_servers (id, tenant_id, name, transport, trust_score, status) VALUES ($1, $2, 'server-a', 'http', 0.9, 'active')`,
			args:  []any{serverAID, tenantID},
		},
		{
			query: `INSERT INTO mcp_servers (id, tenant_id, name, transport, trust_score, status) VALUES ($1, $2, 'server-b', 'http', 0.4, 'active')`,
			args:  []any{serverBID, tenantID},
		},
		{
			query: `INSERT INTO sessions (id, tenant_id, agent_id, mcp_server_id, external_id, protocol_version, transport, state, started_at)
			        VALUES ($1, $2, $3, $4, $5, '2025-11-25', 'http', 'ready', NOW())`,
			args: []any{sessionID, tenantID, agentID, serverAID, "integration-session-" + sessionID[:8]},
		},
	}

	for _, stmt := range statements {
		if _, err := db.Pool().Exec(ctx, stmt.query, stmt.args...); err != nil {
			t.Fatalf("seed fixture: %v", err)
		}
	}
}
