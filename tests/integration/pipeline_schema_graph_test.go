//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mcpids/mcpids/internal/diff"
	"github.com/mcpids/mcpids/internal/gateway"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/mcp"
	"github.com/mcpids/mcpids/internal/policy"
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/internal/risk"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/session"
	"github.com/mcpids/mcpids/pkg/types"
)

func newTestPipeline(t *testing.T) (*gateway.Pipeline, schemapkg.Validator) {
	t.Helper()

	rulesEngine, err := rules.NewEngine(context.Background(), nil)
	if err != nil {
		t.Fatalf("rules.NewEngine: %v", err)
	}

	validator := schemapkg.NewValidator()
	pl := gateway.NewPipeline(gateway.PipelineOptions{
		Policy: policy.NewEngine(policy.Options{
			RulesEngine:    rulesEngine,
			RiskEngine:     risk.NewEngine(risk.DefaultWeights),
			SemanticEngine: nil,
		}),
		Diff:            diff.NewEngine(),
		Graph:           graph.NewEngine(),
		Schema:          validator,
		Sessions:        session.NewManager(nil),
		MaxEvalDuration: 100 * time.Millisecond,
		FailOpen:        false,
	})
	return pl, validator
}

func TestPipelineSchemaViolationDenied(t *testing.T) {
	pl, validator := newTestPipeline(t)
	sess := &mcp.Session{
		ID:       "11111111-1111-1111-1111-111111111111",
		TenantID: "00000000-0000-0000-0000-000000000001",
		AgentID:  "00000000-0000-0000-0000-000000000002",
		ServerID: "00000000-0000-0000-0000-000000000003",
		State:    mcp.StateReady,
	}

	err := validator.RegisterToolSchema(context.Background(), sess.ServerID, "lookup", json.RawMessage(`{
		"type":"object",
		"additionalProperties":false,
		"required":["q"],
		"properties":{"q":{"type":"string"}}
	}`))
	if err != nil {
		t.Fatalf("RegisterToolSchema: %v", err)
	}

	result := pl.Run(context.Background(), &gateway.InterceptRequest{
		Message: &mcp.JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`"1"`),
			Method:  mcp.MethodToolsCall,
			Params:  json.RawMessage(`{"name":"lookup","arguments":{"q":123}}`),
		},
		Method:    mcp.MethodToolsCall,
		Direction: mcp.DirectionInbound,
		Session:   sess,
		ServerID:  sess.ServerID,
	})

	if result == nil || result.Verdict == nil {
		t.Fatal("expected verdict")
	}
	if !result.Blocked || result.Verdict.Decision != types.DecisionDeny {
		t.Fatalf("expected deny+blocked for schema violation, got blocked=%v decision=%s", result.Blocked, result.Verdict.Decision)
	}
}

func TestPipelineGraphLateralMovementMonitorOnly(t *testing.T) {
	pl, validator := newTestPipeline(t)
	sess := &mcp.Session{
		ID:       "22222222-2222-2222-2222-222222222222",
		TenantID: "00000000-0000-0000-0000-000000000001",
		AgentID:  "00000000-0000-0000-0000-000000000002",
		State:    mcp.StateReady,
	}

	for _, serverID := range []string{
		"00000000-0000-0000-0000-000000000003",
		"00000000-0000-0000-0000-000000000004",
		"00000000-0000-0000-0000-000000000005",
	} {
		if err := validator.RegisterToolSchema(context.Background(), serverID, "read_file", json.RawMessage(`null`)); err != nil {
			t.Fatalf("RegisterToolSchema: %v", err)
		}

		sess.ServerID = serverID
		result := pl.Run(context.Background(), &gateway.InterceptRequest{
			Message: &mcp.JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`"1"`),
				Method:  mcp.MethodToolsCall,
				Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/a"}}`),
			},
			Method:    mcp.MethodToolsCall,
			Direction: mcp.DirectionInbound,
			Session:   sess,
			ServerID:  serverID,
		})
		if serverID == "00000000-0000-0000-0000-000000000005" {
			if result == nil || result.Verdict == nil {
				t.Fatal("expected verdict")
			}
			if result.Verdict.Decision != types.DecisionMonitorOnly {
				t.Fatalf("expected monitor_only from graph signal, got %s", result.Verdict.Decision)
			}
		}
	}
}
