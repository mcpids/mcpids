package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	approvalspkg "github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/diff"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/gateway"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/mcp"
	"github.com/mcpids/mcpids/internal/policy"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/semantic"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
)

// WrapperManager manages a pool of stdio-wrapped MCP server processes.
// Each wrapped process runs behind the gateway pipeline so all traffic is inspected.
type WrapperManager struct {
	tenantID string
	agentID  string
	maxProcs int

	policyEngine policy.Engine
	diffEngine   diff.Engine
	graphEngine  graph.Engine
	schema       schemapkg.Validator
	semantic     semantic.Classifier
	sessions     sessionpkg.Manager
	approvals    approvalspkg.Workflow
	recorder     eventspkg.Recorder
	metrics      *gateway.PipelineMetrics

	mu       sync.Mutex
	wrappers map[string]*wrappedProc // serverID → wrapper
}

type wrappedProc struct {
	serverID string
	entry    ServerEntry
	proxy    *gateway.StdioProxy
	cancel   context.CancelFunc
}

// NewWrapperManager creates a WrapperManager with the given engine dependencies.
func NewWrapperManager(
	tenantID, agentID string,
	maxProcs int,
	policyEngine policy.Engine,
	diffEngine diff.Engine,
	graphEngine graph.Engine,
	schemaValidator schemapkg.Validator,
	semanticClassifier semantic.Classifier,
	sessions sessionpkg.Manager,
	approvals approvalspkg.Workflow,
	recorder eventspkg.Recorder,
	metrics *gateway.PipelineMetrics,
) *WrapperManager {
	if maxProcs <= 0 {
		maxProcs = 10
	}
	return &WrapperManager{
		tenantID:     tenantID,
		agentID:      agentID,
		maxProcs:     maxProcs,
		policyEngine: policyEngine,
		diffEngine:   diffEngine,
		graphEngine:  graphEngine,
		schema:       schemaValidator,
		semantic:     semanticClassifier,
		sessions:     sessions,
		approvals:    approvals,
		recorder:     recorder,
		metrics:      metrics,
		wrappers:     make(map[string]*wrappedProc),
	}
}

// Wrap launches the given ServerEntry as a wrapped stdio subprocess.
// The process is started under the gateway pipeline for traffic inspection.
// Returns the server ID assigned to this process.
func (m *WrapperManager) Wrap(ctx context.Context, entry ServerEntry, serverID string) (string, error) {
	if entry.Transport != "stdio" {
		return "", fmt.Errorf("wrapper: only stdio servers can be wrapped, got %q", entry.Transport)
	}
	if len(entry.Command) == 0 {
		return "", fmt.Errorf("wrapper: server %q has no command", entry.Name)
	}
	if serverID == "" {
		serverID = uuid.New().String()
	}

	m.mu.Lock()
	if _, exists := m.wrappers[serverID]; exists {
		m.mu.Unlock()
		return serverID, nil
	}
	if len(m.wrappers) >= m.maxProcs {
		m.mu.Unlock()
		return "", fmt.Errorf("wrapper: max process limit (%d) reached", m.maxProcs)
	}
	m.mu.Unlock()

	// Create a synthetic session for this stdio process.
	sess := &mcp.Session{
		TenantID:  m.tenantID,
		AgentID:   m.agentID,
		ServerID:  serverID,
		Transport: "stdio",
		State:     mcp.StateNew,
	}
	if m.sessions != nil {
		if err := m.sessions.Create(ctx, sess); err != nil {
			slog.Warn("wrapper: failed to create session", "server", entry.Name, "error", err)
		}
	}

	// Build pipeline.
	pl := gateway.NewPipeline(gateway.PipelineOptions{
		Policy:    m.policyEngine,
		Diff:      m.diffEngine,
		Graph:     m.graphEngine,
		Schema:    m.schema,
		Semantic:  m.semantic,
		Sessions:  m.sessions,
		Approvals: m.approvals,
		Recorder:  m.recorder,
		Metrics:   m.metrics,
		FailOpen:  false,
	})

	proxy := gateway.NewStdioProxy(entry.Command, pl, sess, serverID, mcp.DefaultMaxMessageSize)

	procCtx, cancel := context.WithCancel(ctx)

	wp := &wrappedProc{
		serverID: serverID,
		entry:    entry,
		proxy:    proxy,
		cancel:   cancel,
	}

	m.mu.Lock()
	m.wrappers[serverID] = wp
	m.mu.Unlock()

	// Start the proxy goroutine.
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.wrappers, serverID)
			m.mu.Unlock()
			cancel()
		}()
		if err := proxy.Run(procCtx); err != nil {
			slog.Warn("wrapper: process exited",
				"server", entry.Name,
				"server_id", serverID,
				"error", err)
		}
	}()

	slog.Info("wrapper: started",
		"server", entry.Name,
		"server_id", serverID,
		"command", entry.Command)

	return serverID, nil
}

// Stop terminates the wrapped process with the given server ID.
func (m *WrapperManager) Stop(serverID string) {
	m.mu.Lock()
	wp, ok := m.wrappers[serverID]
	m.mu.Unlock()
	if ok {
		wp.cancel()
	}
}

// StopAll terminates all wrapped processes.
func (m *WrapperManager) StopAll() {
	m.mu.Lock()
	wps := make([]*wrappedProc, 0, len(m.wrappers))
	for _, wp := range m.wrappers {
		wps = append(wps, wp)
	}
	m.mu.Unlock()

	for _, wp := range wps {
		wp.cancel()
	}
}

// ActiveCount returns the number of currently running wrapped processes.
func (m *WrapperManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.wrappers)
}
