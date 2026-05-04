//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mcpids/mcpids/internal/config"
	"github.com/mcpids/mcpids/internal/controlplane"
	"github.com/mcpids/mcpids/internal/graph"
	mcppkg "github.com/mcpids/mcpids/internal/mcp"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

func TestControlPlanePublishEventUpdatesSessionGraph(t *testing.T) {
	graphEngine := graph.NewEngine()
	srv := controlplane.New(controlplane.Options{
		Config:      config.ControlPlaneDefaults(),
		GraphEngine: graphEngine,
	})

	payload, err := json.Marshal(&mcppkg.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  mcppkg.MethodToolsCall,
		Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/demo.txt"}}`),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	_, err = srv.PublishEvent(context.Background(), &mcpidsv1.Event{
		EventId:     "event-1",
		Kind:        mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL,
		TenantId:    "00000000-0000-0000-0000-000000000001",
		AgentId:     "00000000-0000-0000-0000-000000000002",
		SessionId:   "00000000-0000-0000-0000-000000000010",
		ServerId:    "00000000-0000-0000-0000-000000000003",
		Timestamp:   time.Now().UTC().UnixMilli(),
		PayloadJson: payload,
	})
	if err != nil {
		t.Fatalf("PublishEvent: %v", err)
	}

	nodes, edges, err := graphEngine.GetSessionGraph(context.Background(), "00000000-0000-0000-0000-000000000010")
	if err != nil {
		t.Fatalf("GetSessionGraph: %v", err)
	}
	if len(nodes) == 0 || len(edges) == 0 {
		t.Fatalf("expected graph nodes and edges, got nodes=%d edges=%d", len(nodes), len(edges))
	}
}
