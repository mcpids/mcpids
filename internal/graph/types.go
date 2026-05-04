// Package graph implements the MCP call graph engine.
// It tracks relationships between agents, sessions, MCP servers, tools, and resources
// and detects suspicious access patterns such as lateral movement, chain exfiltration,
// and unusual cross-server access.
package graph

import (
	"time"
)

// NodeKind classifies a node in the call graph.
type NodeKind string

const (
	NodeKindAgent    NodeKind = "agent"
	NodeKindSession  NodeKind = "session"
	NodeKindServer   NodeKind = "server"
	NodeKindTool     NodeKind = "tool"
	NodeKindResource NodeKind = "resource"
)

// EdgeKind classifies a directed relationship in the call graph.
type EdgeKind string

const (
	EdgeKindCalls          EdgeKind = "calls"           // agent/session → tool
	EdgeKindAccesses       EdgeKind = "accesses"        // agent/session → resource
	EdgeKindConnectsTo     EdgeKind = "connects_to"     // agent → server
	EdgeKindBelongsTo      EdgeKind = "belongs_to"      // session → server
	EdgeKindOutputFlowsTo  EdgeKind = "output_flows_to" // tool → tool (chained output)
)

// Node represents a vertex in the call graph.
type Node struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Kind      NodeKind          `json:"kind"`
	Label     string            `json:"label"` // human-readable name
	Attrs     map[string]string `json:"attrs,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	CallCount int               `json:"call_count"`
}

// Edge represents a directed relationship between two nodes.
type Edge struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	FromID    string            `json:"from_id"`
	ToID      string            `json:"to_id"`
	Kind      EdgeKind          `json:"kind"`
	Weight    float64           `json:"weight"` // frequency / risk weight
	SessionID string            `json:"session_id"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// GraphPath is a sequence of nodes forming a call chain.
type GraphPath struct {
	Nodes []string  // ordered list of node IDs
	Edges []string  // ordered list of edge IDs
	Score float64   // risk score for this path
}

// Signal is the risk contribution produced by the graph engine for a message.
type Signal struct {
	// LateralMovement is true when the agent accessed multiple distinct servers in a window.
	LateralMovement bool `json:"lateral_movement"`

	// ChainDepth is the maximum tool call chain depth detected for this session.
	ChainDepth int `json:"chain_depth"`

	// SuspiciousPaths contains descriptions of flagged access patterns.
	SuspiciousPaths []string `json:"suspicious_paths,omitempty"`

	// UniqueServerCount is how many distinct servers the agent has accessed.
	UniqueServerCount int `json:"unique_server_count"`

	// RiskContribution is the 0.0–1.0 contribution to the overall risk score.
	RiskContribution float64 `json:"risk_contribution"`
}

// AgentSignal is the cross-session risk analysis for a single agent.
// Unlike Signal (which is scoped to one session), AgentSignal correlates
// behaviour across all sessions the agent has participated in.
type AgentSignal struct {
	// TotalSessions is the number of distinct sessions observed for the agent.
	TotalSessions int `json:"total_sessions"`

	// TotalServers is the number of distinct MCP servers the agent has reached
	// across all sessions.
	TotalServers int `json:"total_servers"`

	// RepeatedLateralMovement is true when the agent performed lateral movement
	// (accessed >1 server) in more than one session.
	RepeatedLateralMovement bool `json:"repeated_lateral_movement"`

	// CrossSessionChainDepth is the cumulative tool call chain depth across all
	// sessions - a proxy for persistence and automation level.
	CrossSessionChainDepth int `json:"cross_session_chain_depth"`

	// SuspiciousPaths contains descriptions of flagged cross-session patterns.
	SuspiciousPaths []string `json:"suspicious_paths,omitempty"`

	// RiskScore is the 0.0-1.0 cross-session risk score for the agent.
	RiskScore float64 `json:"risk_score"`
}

// CallRecord represents a single observed tool call to be added to the graph.
type CallRecord struct {
	TenantID  string
	AgentID   string
	SessionID string
	ServerID  string
	ToolName  string
	CalledAt  time.Time
}

// ResourceAccessRecord represents a single observed resource access.
type ResourceAccessRecord struct {
	TenantID  string
	AgentID   string
	SessionID string
	ServerID  string
	ResourceURI string
	AccessedAt  time.Time
}
