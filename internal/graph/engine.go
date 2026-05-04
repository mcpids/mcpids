package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine records MCP call relationships and analyzes them for suspicious patterns.
type Engine interface {
	// RecordCall records a tool call and updates the graph.
	RecordCall(ctx context.Context, rec CallRecord) error

	// RecordResourceAccess records a resource access and updates the graph.
	RecordResourceAccess(ctx context.Context, rec ResourceAccessRecord) error

	// Analyze examines recent graph activity for a session and returns a risk signal.
	Analyze(ctx context.Context, tenantID, sessionID string) (*Signal, error)

	// GetSessionGraph returns all nodes and edges for a given session.
	GetSessionGraph(ctx context.Context, sessionID string) ([]Node, []Edge, error)

	// GetAgentGraph returns all nodes and edges observed for a given agent
	// within the given time window.
	GetAgentGraph(ctx context.Context, agentID string, since time.Time) ([]Node, []Edge, error)

	// AnalyzeAgent correlates activity across all sessions for an agent and
	// returns a cross-session risk signal.
	AnalyzeAgent(ctx context.Context, tenantID, agentID string) (*AgentSignal, error)
}

// engineImpl is the in-memory graph engine.
// Production use should persist to PostgreSQL for durability across restarts.
type engineImpl struct {
	mu    sync.RWMutex
	nodes map[string]*Node // node ID → node
	edges []*Edge          // all edges (append-only for MVP)
	store Store

	// Per-agent server access: agentID → set of serverIDs
	agentServers map[string]map[string]struct{}

	// Per-session tool call chain: sessionID → ordered list of tool node IDs
	sessionChain map[string][]string

	// Per-session server set: sessionID → set of serverIDs
	sessionServers map[string]map[string]struct{}

	// Per-agent session set: agentID → set of sessionIDs (cross-session tracking)
	agentSessions map[string]map[string]struct{}
}

// NewEngine creates an in-memory graph engine.
func NewEngine() Engine {
	return NewEngineWithStore(nil)
}

// NewEngineWithStore creates a graph engine with optional durable persistence.
func NewEngineWithStore(store Store) Engine {
	return &engineImpl{
		nodes:          make(map[string]*Node),
		agentServers:   make(map[string]map[string]struct{}),
		sessionChain:   make(map[string][]string),
		sessionServers: make(map[string]map[string]struct{}),
		agentSessions:  make(map[string]map[string]struct{}),
		store:          store,
	}
}

// RecordCall implements Engine.
func (e *engineImpl) RecordCall(ctx context.Context, rec CallRecord) error {
	now := rec.CalledAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()

	// Ensure agent node exists.
	agentNode := e.ensureNode(rec.TenantID, rec.AgentID, NodeKindAgent, rec.AgentID)

	// Ensure session node exists.
	sessionNode := e.ensureNode(rec.TenantID, rec.SessionID, NodeKindSession, rec.SessionID)

	// Ensure server node exists.
	serverNode := e.ensureNode(rec.TenantID, rec.ServerID, NodeKindServer, rec.ServerID)

	// Ensure tool node exists (keyed by server+tool to allow same-named tools on different servers).
	toolKey := rec.ServerID + ":" + rec.ToolName
	toolNode := e.ensureNode(rec.TenantID, toolKey, NodeKindTool, rec.ToolName)
	toolNode.CallCount++
	toolNode.LastSeen = now

	// Record edges.
	e.ensureEdge(rec.TenantID, agentNode.ID, serverNode.ID, EdgeKindConnectsTo, rec.SessionID)
	e.ensureEdge(rec.TenantID, sessionNode.ID, serverNode.ID, EdgeKindBelongsTo, rec.SessionID)
	e.ensureEdge(rec.TenantID, sessionNode.ID, toolNode.ID, EdgeKindCalls, rec.SessionID)

	// Track per-agent server set.
	if e.agentServers[rec.AgentID] == nil {
		e.agentServers[rec.AgentID] = make(map[string]struct{})
	}
	e.agentServers[rec.AgentID][rec.ServerID] = struct{}{}

	// Track per-session server set.
	if e.sessionServers[rec.SessionID] == nil {
		e.sessionServers[rec.SessionID] = make(map[string]struct{})
	}
	e.sessionServers[rec.SessionID][rec.ServerID] = struct{}{}

	// Track per-agent session set for cross-session analytics.
	if e.agentSessions[rec.AgentID] == nil {
		e.agentSessions[rec.AgentID] = make(map[string]struct{})
	}
	e.agentSessions[rec.AgentID][rec.SessionID] = struct{}{}

	// Track per-session tool call chain.
	var prevToolKey string
	if chain := e.sessionChain[rec.SessionID]; len(chain) > 0 {
		prevToolKey = chain[len(chain)-1]
	}
	e.sessionChain[rec.SessionID] = append(e.sessionChain[rec.SessionID], toolKey)

	// Detect consecutive chained calls (last tool → this tool).
	chain := e.sessionChain[rec.SessionID]
	if len(chain) > 1 {
		prevToolKey := chain[len(chain)-2]
		e.ensureEdge(rec.TenantID, prevToolKey, toolKey, EdgeKindOutputFlowsTo, rec.SessionID)
	}

	slog.Debug("graph: call recorded",
		"agent", rec.AgentID,
		"session", rec.SessionID,
		"server", rec.ServerID,
		"tool", rec.ToolName,
		"chain_depth", len(chain))
	e.mu.Unlock()

	if e.store != nil {
		if err := e.store.RecordCall(ctx, rec, prevToolKey); err != nil {
			slog.Warn("graph: persist call failed",
				"tenant", rec.TenantID,
				"session", rec.SessionID,
				"tool", rec.ToolName,
				"error", err)
		}
	}

	return nil
}

// RecordResourceAccess implements Engine.
func (e *engineImpl) RecordResourceAccess(ctx context.Context, rec ResourceAccessRecord) error {
	now := rec.AccessedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()

	agentNode := e.ensureNode(rec.TenantID, rec.AgentID, NodeKindAgent, rec.AgentID)
	sessionNode := e.ensureNode(rec.TenantID, rec.SessionID, NodeKindSession, rec.SessionID)
	serverNode := e.ensureNode(rec.TenantID, rec.ServerID, NodeKindServer, rec.ServerID)
	resourceNode := e.ensureNode(rec.TenantID, rec.ResourceURI, NodeKindResource, rec.ResourceURI)
	resourceNode.LastSeen = now

	e.ensureEdge(rec.TenantID, agentNode.ID, serverNode.ID, EdgeKindConnectsTo, rec.SessionID)
	e.ensureEdge(rec.TenantID, sessionNode.ID, resourceNode.ID, EdgeKindAccesses, rec.SessionID)

	if e.agentServers[rec.AgentID] == nil {
		e.agentServers[rec.AgentID] = make(map[string]struct{})
	}
	e.agentServers[rec.AgentID][rec.ServerID] = struct{}{}

	if e.agentSessions[rec.AgentID] == nil {
		e.agentSessions[rec.AgentID] = make(map[string]struct{})
	}
	e.agentSessions[rec.AgentID][rec.SessionID] = struct{}{}
	e.mu.Unlock()

	if e.store != nil {
		if err := e.store.RecordResourceAccess(ctx, rec); err != nil {
			slog.Warn("graph: persist resource access failed",
				"tenant", rec.TenantID,
				"session", rec.SessionID,
				"resource", rec.ResourceURI,
				"error", err)
		}
	}

	return nil
}

// Analyze implements Engine.
func (e *engineImpl) Analyze(ctx context.Context, tenantID, sessionID string) (*Signal, error) {
	if e.store != nil {
		sig, err := e.store.Analyze(ctx, tenantID, sessionID)
		if err == nil {
			return sig, nil
		}
		slog.Warn("graph: persistent analyze failed, using in-memory state",
			"tenant", tenantID,
			"session", sessionID,
			"error", err)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	sig := &Signal{}

	// Unique server count for this session.
	sessionSrvs := e.sessionServers[sessionID]
	sig.UniqueServerCount = len(sessionSrvs)

	// Lateral movement: session accessed > 1 distinct server.
	if sig.UniqueServerCount > 1 {
		sig.LateralMovement = true
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("session accessed %d distinct servers", sig.UniqueServerCount))
	}

	// Chain depth.
	sig.ChainDepth = len(e.sessionChain[sessionID])

	// Risk scoring.
	var score float64
	if sig.LateralMovement {
		score += 0.3 * float64(sig.UniqueServerCount-1)
	}
	if sig.ChainDepth > 5 {
		score += 0.2 * float64(sig.ChainDepth-5) / 10.0
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("deep tool call chain (depth=%d)", sig.ChainDepth))
	}
	if score > 1.0 {
		score = 1.0
	}
	sig.RiskContribution = score

	return sig, nil
}

// AnalyzeAgent implements Engine.
// It correlates activity across all sessions for the given agent and returns
// a cross-session risk signal. The store path is skipped for the in-memory
// engine (there is no persistent cross-session query yet).
func (e *engineImpl) AnalyzeAgent(ctx context.Context, tenantID, agentID string) (*AgentSignal, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sig := &AgentSignal{}

	// --- session count ---
	sessions := e.agentSessions[agentID]
	sig.TotalSessions = len(sessions)

	// --- total distinct servers across all sessions ---
	sig.TotalServers = len(e.agentServers[agentID])

	// --- cross-session chain depth and lateral-movement count ---
	lateralSessions := 0
	for sid := range sessions {
		sig.CrossSessionChainDepth += len(e.sessionChain[sid])
		if len(e.sessionServers[sid]) > 1 {
			lateralSessions++
		}
	}

	if lateralSessions > 1 {
		sig.RepeatedLateralMovement = true
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("lateral movement observed in %d/%d sessions", lateralSessions, sig.TotalSessions))
	}

	if sig.TotalServers > 3 {
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("agent reached %d distinct servers across all sessions", sig.TotalServers))
	}

	if sig.CrossSessionChainDepth > 20 {
		sig.SuspiciousPaths = append(sig.SuspiciousPaths,
			fmt.Sprintf("high cumulative tool call depth across sessions (%d)", sig.CrossSessionChainDepth))
	}

	// --- risk scoring ---
	var score float64
	if sig.RepeatedLateralMovement {
		score += 0.4
	}
	if sig.TotalServers > 1 {
		score += 0.1 * float64(sig.TotalServers-1)
	}
	if sig.CrossSessionChainDepth > 20 {
		score += 0.1 * float64(sig.CrossSessionChainDepth-20) / 20.0
	}
	if score > 1.0 {
		score = 1.0
	}
	sig.RiskScore = score

	slog.Debug("graph: agent cross-session analysis",
		"agent", agentID,
		"sessions", sig.TotalSessions,
		"servers", sig.TotalServers,
		"chain_depth", sig.CrossSessionChainDepth,
		"risk", sig.RiskScore)

	return sig, nil
}

// GetSessionGraph implements Engine.
func (e *engineImpl) GetSessionGraph(ctx context.Context, sessionID string) ([]Node, []Edge, error) {
	if e.store != nil {
		nodes, edges, err := e.store.GetSessionGraph(ctx, sessionID)
		if err == nil {
			return nodes, edges, nil
		}
		slog.Warn("graph: persistent session graph failed, using in-memory state",
			"session", sessionID,
			"error", err)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var nodes []Node
	var edges []Edge

	for _, edge := range e.edges {
		if edge.SessionID == sessionID {
			edges = append(edges, *edge)
			if n, ok := e.nodes[edge.FromID]; ok {
				nodes = append(nodes, *n)
			}
			if n, ok := e.nodes[edge.ToID]; ok {
				nodes = append(nodes, *n)
			}
		}
	}

	return deduplicateNodes(nodes), edges, nil
}

// GetAgentGraph implements Engine.
func (e *engineImpl) GetAgentGraph(ctx context.Context, agentID string, since time.Time) ([]Node, []Edge, error) {
	if e.store != nil {
		nodes, edges, err := e.store.GetAgentGraph(ctx, agentID, since)
		if err == nil {
			return nodes, edges, nil
		}
		slog.Warn("graph: persistent agent graph failed, using in-memory state",
			"agent", agentID,
			"error", err)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	agentNodeID := agentID

	var edges []Edge
	reachableNodeIDs := make(map[string]bool)
	reachableNodeIDs[agentNodeID] = true

	for _, edge := range e.edges {
		if edge.FromID == agentNodeID || edge.ToID == agentNodeID {
			if edge.CreatedAt.After(since) {
				edges = append(edges, *edge)
				reachableNodeIDs[edge.FromID] = true
				reachableNodeIDs[edge.ToID] = true
			}
		}
	}

	// Also collect edges between reachable nodes (one hop deeper).
	for _, edge := range e.edges {
		if reachableNodeIDs[edge.FromID] && reachableNodeIDs[edge.ToID] {
			if edge.CreatedAt.After(since) {
				// Deduplicate: only add if not already collected.
				found := false
				for _, existing := range edges {
					if existing.ID == edge.ID {
						found = true
						break
					}
				}
				if !found {
					edges = append(edges, *edge)
				}
			}
		}
	}

	// Return only nodes reachable from the agent.
	var nodes []Node
	for id := range reachableNodeIDs {
		if n, ok := e.nodes[id]; ok {
			nodes = append(nodes, *n)
		}
	}

	return nodes, edges, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// ensureNode returns the existing node with the given ID, or creates it.
// Must be called with e.mu held.
func (e *engineImpl) ensureNode(tenantID, id string, kind NodeKind, label string) *Node {
	if n, ok := e.nodes[id]; ok {
		n.LastSeen = time.Now().UTC()
		return n
	}
	n := &Node{
		ID:        id,
		TenantID:  tenantID,
		Kind:      kind,
		Label:     label,
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	e.nodes[id] = n
	return n
}

// ensureEdge finds or creates an edge. Returns the edge.
// Must be called with e.mu held.
func (e *engineImpl) ensureEdge(tenantID, fromID, toID string, kind EdgeKind, sessionID string) *Edge {
	for _, edge := range e.edges {
		if edge.FromID == fromID && edge.ToID == toID && edge.Kind == kind {
			edge.Weight++
			return edge
		}
	}
	edge := &Edge{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		FromID:    fromID,
		ToID:      toID,
		Kind:      kind,
		Weight:    1,
		SessionID: sessionID,
		CreatedAt: time.Now().UTC(),
	}
	e.edges = append(e.edges, edge)
	return edge
}

func deduplicateNodes(nodes []Node) []Node {
	seen := make(map[string]bool, len(nodes))
	result := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if !seen[n.ID] {
			seen[n.ID] = true
			result = append(result, n)
		}
	}
	return result
}
