// Package bench contains micro-benchmarks and a soak test for the MCPIDS hot
// path.  Run with:
//
//	go test ./tests/bench/ -bench=. -benchmem
//
// Soak test (skipped under -short):
//
//	go test ./tests/bench/ -run=TestSoak -soak-duration=60s
package bench_test

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
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
)

var soakDuration = flag.Duration("soak-duration", 30*time.Second, "how long to run the soak test")

// ─── helpers ─────────────────────────────────────────────────────────────────

func newBenchPipeline(b *testing.B) *gateway.Pipeline {
	b.Helper()
	rulesEngine, err := rules.NewEngine(context.Background(), nil)
	if err != nil {
		b.Fatalf("rules.NewEngine: %v", err)
	}
	return gateway.NewPipeline(gateway.PipelineOptions{
		Policy: policy.NewEngine(policy.Options{
			RulesEngine:    rulesEngine,
			RiskEngine:     risk.NewEngine(risk.DefaultWeights),
			SemanticEngine: nil,
		}),
		Diff:            diff.NewEngine(),
		Graph:           graph.NewEngine(),
		Schema:          schemapkg.NewValidator(),
		Sessions:        session.NewManager(nil),
		MaxEvalDuration: 100 * time.Millisecond,
		FailOpen:        true,
	})
}

func newBenchSession(id string) *mcp.Session {
	return &mcp.Session{
		ID:       id,
		TenantID: "00000000-0000-0000-0000-000000000001",
		AgentID:  "00000000-0000-0000-0000-000000000002",
		ServerID: "00000000-0000-0000-0000-000000000003",
		State:    mcp.StateReady,
	}
}

var toolsCallMsg = &mcp.JSONRPCMessage{
	JSONRPC: "2.0",
	ID:      json.RawMessage(`"1"`),
	Method:  mcp.MethodToolsCall,
	Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/data.txt"}}`),
}

// ─── Graph engine benchmarks ──────────────────────────────────────────────────

// BenchmarkGraphEngine_RecordCall measures raw call-record throughput.
func BenchmarkGraphEngine_RecordCall(b *testing.B) {
	eng := graph.NewEngine()
	ctx := context.Background()
	rec := graph.CallRecord{
		TenantID:  "t1",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ServerID:  "server-A",
		ToolName:  "read_file",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.CalledAt = time.Now()
		if err := eng.RecordCall(ctx, rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGraphEngine_RecordCall_Parallel stresses concurrent write throughput.
func BenchmarkGraphEngine_RecordCall_Parallel(b *testing.B) {
	eng := graph.NewEngine()
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = eng.RecordCall(ctx, graph.CallRecord{
				TenantID:  "t1",
				AgentID:   fmt.Sprintf("agent-%d", i%4),
				SessionID: fmt.Sprintf("sess-%d", i%16),
				ServerID:  fmt.Sprintf("server-%d", i%3),
				ToolName:  "tool",
				CalledAt:  time.Now(),
			})
			i++
		}
	})
}

// BenchmarkGraphEngine_Analyze measures single-session analysis throughput.
func BenchmarkGraphEngine_Analyze(b *testing.B) {
	eng := graph.NewEngine()
	ctx := context.Background()
	// Pre-populate: 3 servers, 10-call chain.
	for i := 0; i < 10; i++ {
		_ = eng.RecordCall(ctx, graph.CallRecord{
			TenantID:  "t1",
			AgentID:   "agent-1",
			SessionID: "sess-1",
			ServerID:  fmt.Sprintf("server-%d", i%3),
			ToolName:  fmt.Sprintf("tool-%d", i),
			CalledAt:  time.Now(),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Analyze(ctx, "t1", "sess-1"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGraphEngine_AnalyzeAgent measures cross-session analysis throughput.
func BenchmarkGraphEngine_AnalyzeAgent(b *testing.B) {
	eng := graph.NewEngine()
	ctx := context.Background()
	// Pre-populate: 5 sessions, 3 servers each, 8-call chain each.
	for s := 0; s < 5; s++ {
		for i := 0; i < 8; i++ {
			_ = eng.RecordCall(ctx, graph.CallRecord{
				TenantID:  "t1",
				AgentID:   "agent-1",
				SessionID: fmt.Sprintf("sess-%d", s),
				ServerID:  fmt.Sprintf("server-%d", i%3),
				ToolName:  fmt.Sprintf("tool-%d", i),
				CalledAt:  time.Now(),
			})
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.AnalyzeAgent(ctx, "t1", "agent-1"); err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Pipeline benchmarks ──────────────────────────────────────────────────────

// BenchmarkPipeline_ToolsCall measures end-to-end interception latency for a
// single tools/call message.
func BenchmarkPipeline_ToolsCall(b *testing.B) {
	pl := newBenchPipeline(b)
	ctx := context.Background()
	sess := newBenchSession("11111111-1111-1111-1111-111111111111")
	req := &gateway.InterceptRequest{
		Message:   toolsCallMsg,
		Method:    mcp.MethodToolsCall,
		Direction: mcp.DirectionInbound,
		Session:   sess,
		ServerID:  sess.ServerID,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pl.Run(ctx, req)
	}
}

// BenchmarkPipeline_ToolsCall_Parallel stresses the pipeline under concurrent load
// matching the number of available CPUs.
func BenchmarkPipeline_ToolsCall_Parallel(b *testing.B) {
	pl := newBenchPipeline(b)
	ctx := context.Background()
	sess := newBenchSession("22222222-2222-2222-2222-222222222222")
	req := &gateway.InterceptRequest{
		Message:   toolsCallMsg,
		Method:    mcp.MethodToolsCall,
		Direction: mcp.DirectionInbound,
		Session:   sess,
		ServerID:  sess.ServerID,
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pl.Run(ctx, req)
		}
	})
}

// BenchmarkPipeline_ToolsList benchmarks the less common but heavier list response path.
func BenchmarkPipeline_ToolsList(b *testing.B) {
	pl := newBenchPipeline(b)
	ctx := context.Background()
	sess := newBenchSession("33333333-3333-3333-3333-333333333333")
	msg := &mcp.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"2"`),
		Method:  mcp.MethodToolsList,
		Result: json.RawMessage(`{"tools":[
			{"name":"read_file","description":"Read a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}},
			{"name":"write_file","description":"Write a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}}
		]}`),
	}
	req := &gateway.InterceptRequest{
		Message:   msg,
		Method:    mcp.MethodToolsList,
		Direction: mcp.DirectionOutbound,
		Session:   sess,
		ServerID:  sess.ServerID,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pl.Run(ctx, req)
	}
}

// ─── Soak test ────────────────────────────────────────────────────────────────

// TestSoak_Pipeline runs the pipeline at sustained load for soakDuration,
// collecting throughput and error-rate metrics.  Skipped under -short.
func TestSoak_Pipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test under -short")
	}

	pl := func() *gateway.Pipeline {
		rulesEngine, err := rules.NewEngine(context.Background(), nil)
		if err != nil {
			t.Fatalf("rules.NewEngine: %v", err)
		}
		return gateway.NewPipeline(gateway.PipelineOptions{
			Policy: policy.NewEngine(policy.Options{
				RulesEngine:    rulesEngine,
				RiskEngine:     risk.NewEngine(risk.DefaultWeights),
				SemanticEngine: nil,
			}),
			Diff:            diff.NewEngine(),
			Graph:           graph.NewEngine(),
			Schema:          schemapkg.NewValidator(),
			Sessions:        session.NewManager(nil),
			MaxEvalDuration: 100 * time.Millisecond,
			FailOpen:        true,
		})
	}()

	ctx := context.Background()
	workers := runtime.NumCPU()
	dur := *soakDuration

	var (
		ops    atomic.Int64
		errors atomic.Int64
	)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			sess := newBenchSession(fmt.Sprintf("soak-sess-%d", workerID))
			req := &gateway.InterceptRequest{
				Message:   toolsCallMsg,
				Method:    mcp.MethodToolsCall,
				Direction: mcp.DirectionInbound,
				Session:   sess,
				ServerID:  sess.ServerID,
			}
			for {
				select {
				case <-stop:
					return
				default:
				}
				result := pl.Run(ctx, req)
				ops.Add(1)
				if result == nil {
					errors.Add(1)
				}
			}
		}(w)
	}

	ticker := time.NewTicker(5 * time.Second)
	deadline := time.NewTimer(dur)
	defer ticker.Stop()
	defer deadline.Stop()

	startOps := ops.Load()
	startTime := time.Now()

loop:
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(startTime).Seconds()
			total := ops.Load() - startOps
			errs := errors.Load()
			t.Logf("soak: elapsed=%.0fs ops=%d throughput=%.0f/s errors=%d",
				elapsed, total, float64(total)/elapsed, errs)
		case <-deadline.C:
			break loop
		}
	}

	close(stop)
	wg.Wait()

	total := ops.Load() - startOps
	errs := errors.Load()
	elapsed := time.Since(startTime).Seconds()
	throughput := float64(total) / elapsed
	errRate := float64(errs) / float64(total)

	t.Logf("soak summary: workers=%d duration=%.0fs total_ops=%d throughput=%.0f/s error_rate=%.4f%%",
		workers, elapsed, total, throughput, errRate*100)

	const maxErrorRate = 0.001 // 0.1%
	if errRate > maxErrorRate {
		t.Errorf("error rate %.4f%% exceeds threshold %.4f%%", errRate*100, maxErrorRate*100)
	}
	const minThroughput = 1000.0 // ops/s on a single CPU - very conservative floor
	if throughput < minThroughput {
		t.Errorf("throughput %.0f ops/s below minimum %.0f ops/s", throughput, minThroughput)
	}
}

// TestSoak_GraphEngine exercises the graph engine at sustained concurrent load.
func TestSoak_GraphEngine(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test under -short")
	}

	eng := graph.NewEngine()
	ctx := context.Background()
	workers := runtime.NumCPU()
	dur := *soakDuration

	var ops atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			agentID := fmt.Sprintf("agent-%d", workerID%4)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				sessID := fmt.Sprintf("sess-%d-%d", workerID, i%8)
				_ = eng.RecordCall(ctx, graph.CallRecord{
					TenantID:  "t1",
					AgentID:   agentID,
					SessionID: sessID,
					ServerID:  fmt.Sprintf("server-%d", i%3),
					ToolName:  fmt.Sprintf("tool-%d", i%5),
					CalledAt:  time.Now(),
				})
				if i%10 == 0 {
					_, _ = eng.Analyze(ctx, "t1", sessID)
				}
				if i%50 == 0 {
					_, _ = eng.AnalyzeAgent(ctx, "t1", agentID)
				}
				ops.Add(1)
			}
		}(w)
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()

	elapsed := dur.Seconds()
	total := ops.Load()
	t.Logf("graph soak: workers=%d duration=%.0fs total_ops=%d throughput=%.0f/s",
		workers, elapsed, total, float64(total)/elapsed)
}
