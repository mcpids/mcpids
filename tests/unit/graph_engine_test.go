package unit_test

import (
	"context"
	"testing"
	"time"

	"github.com/mcpids/mcpids/internal/graph"
)

func TestGraphEngine_SingleServer_NoLateralMovement(t *testing.T) {
	eng := graph.NewEngine()
	ctx := context.Background()

	rec := graph.CallRecord{
		TenantID:  "t1",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ServerID:  "server-A",
		ToolName:  "read_file",
		CalledAt:  time.Now(),
	}
	if err := eng.RecordCall(ctx, rec); err != nil {
		t.Fatalf("RecordCall: %v", err)
	}

	sig, err := eng.Analyze(ctx, "t1", "sess-1")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if sig.LateralMovement {
		t.Error("expected no lateral movement with single server")
	}
	if sig.UniqueServerCount != 1 {
		t.Errorf("UniqueServerCount = %d, want 1", sig.UniqueServerCount)
	}
}

func TestGraphEngine_TwoServers_LateralMovement(t *testing.T) {
	eng := graph.NewEngine()
	ctx := context.Background()

	base := graph.CallRecord{
		TenantID:  "t1",
		AgentID:   "agent-1",
		SessionID: "sess-2",
		CalledAt:  time.Now(),
	}

	base.ServerID = "server-A"
	base.ToolName = "read_file"
	_ = eng.RecordCall(ctx, base)

	base.ServerID = "server-B"
	base.ToolName = "post_webhook"
	_ = eng.RecordCall(ctx, base)

	sig, err := eng.Analyze(ctx, "t1", "sess-2")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !sig.LateralMovement {
		t.Error("expected lateral movement with two servers")
	}
	if sig.UniqueServerCount != 2 {
		t.Errorf("UniqueServerCount = %d, want 2", sig.UniqueServerCount)
	}
	if sig.RiskContribution <= 0 {
		t.Errorf("RiskContribution = %f, want > 0", sig.RiskContribution)
	}
}

func TestGraphEngine_DeepChain(t *testing.T) {
	eng := graph.NewEngine()
	ctx := context.Background()

	tools := []string{"a", "b", "c", "d", "e", "f", "g"} // 7 deep
	for _, tool := range tools {
		_ = eng.RecordCall(ctx, graph.CallRecord{
			TenantID:  "t1",
			AgentID:   "agent-1",
			SessionID: "sess-chain",
			ServerID:  "server-A",
			ToolName:  tool,
			CalledAt:  time.Now(),
		})
	}

	sig, err := eng.Analyze(ctx, "t1", "sess-chain")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if sig.ChainDepth != len(tools) {
		t.Errorf("ChainDepth = %d, want %d", sig.ChainDepth, len(tools))
	}
	if len(sig.SuspiciousPaths) == 0 {
		t.Error("expected suspicious paths for deep chain")
	}
}

func TestGraphEngine_GetSessionGraph(t *testing.T) {
	eng := graph.NewEngine()
	ctx := context.Background()

	_ = eng.RecordCall(ctx, graph.CallRecord{
		TenantID:  "t1",
		AgentID:   "agent-1",
		SessionID: "sess-graph",
		ServerID:  "server-A",
		ToolName:  "tool-x",
		CalledAt:  time.Now(),
	})

	nodes, edges, err := eng.GetSessionGraph(ctx, "sess-graph")
	if err != nil {
		t.Fatalf("GetSessionGraph: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected nodes in session graph")
	}
	if len(edges) == 0 {
		t.Error("expected edges in session graph")
	}
}

func TestGraphEngine_ResourceAccess(t *testing.T) {
	eng := graph.NewEngine()
	ctx := context.Background()

	_ = eng.RecordResourceAccess(ctx, graph.ResourceAccessRecord{
		TenantID:    "t1",
		AgentID:     "agent-1",
		SessionID:   "sess-res",
		ServerID:    "server-A",
		ResourceURI: "file:///etc/passwd",
		AccessedAt:  time.Now(),
	})

	nodes, edges, err := eng.GetSessionGraph(ctx, "sess-res")
	if err != nil {
		t.Fatalf("GetSessionGraph: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected nodes after resource access")
	}
	if len(edges) == 0 {
		t.Error("expected edges after resource access")
	}
}
