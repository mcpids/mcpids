package mcp

import (
	"time"
)

// SessionState represents the lifecycle state of an MCP session.
// Transitions:
//
//	StateNew → StateInitializing → StateReady → StateClosed
//	StateReady → StateQuarantined → StateClosed
type SessionState int

const (
	StateNew          SessionState = iota // Session record created, no initialize yet
	StateInitializing                     // initialize request received, awaiting response
	StateReady                            // initialize handshake complete, operational
	StateQuarantined                      // session frozen by policy enforcement
	StateClosed                           // session terminated normally
	StateError                            // session terminated due to protocol error
)

func (s SessionState) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateInitializing:
		return "initializing"
	case StateReady:
		return "ready"
	case StateQuarantined:
		return "quarantined"
	case StateClosed:
		return "closed"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Session represents an active MCP protocol session tracked by the gateway or agent.
// Sessions are keyed by the MCP-Session-Id header (HTTP transport) or
// a synthetic ID derived from the stdio process PID and start time.
type Session struct {
	// ID is the internal MCPIDS session UUID (not the MCP-Session-Id header).
	ID string

	// ExternalID is the MCP-Session-Id header value (HTTP) or synthetic pipe ID (stdio).
	ExternalID string

	// TenantID is the tenant this session belongs to.
	TenantID string

	// AgentID is the gateway or agent that owns this session.
	AgentID string

	// ServerID is the registered MCP server UUID. Set after first request completes.
	ServerID string

	// Transport identifies the protocol transport (http, stdio, sse).
	Transport string

	// State is the current lifecycle state.
	State SessionState

	// ProtocolVersion is the negotiated MCP protocol version.
	ProtocolVersion string

	// ClientInfo identifies the MCP client (agent/model).
	ClientInfo Implementation

	// ServerInfo identifies the upstream MCP server.
	ServerInfo Implementation

	// NegotiatedCapabilities holds the server's declared capabilities.
	NegotiatedCapabilities ServerCapabilities

	// QuarantineReason explains why the session was quarantined.
	QuarantineReason string

	// QuarantinedAt records when the quarantine was applied.
	QuarantinedAt *time.Time

	// StartedAt is when the session was created.
	StartedAt time.Time

	// LastSeenAt is the most recent message timestamp.
	LastSeenAt time.Time

	// EndedAt is set when the session transitions to Closed or Error.
	EndedAt *time.Time
}

// IsOperational returns true if the session can process MCP method calls.
func (s *Session) IsOperational() bool {
	return s.State == StateReady
}

// IsBlocked returns true if the session is quarantined or closed.
func (s *Session) IsBlocked() bool {
	return s.State == StateQuarantined || s.State == StateClosed || s.State == StateError
}

// CanTransitionTo returns true if the state transition is valid.
func (s *Session) CanTransitionTo(next SessionState) bool {
	switch s.State {
	case StateNew:
		return next == StateInitializing || next == StateError
	case StateInitializing:
		return next == StateReady || next == StateError
	case StateReady:
		return next == StateQuarantined || next == StateClosed
	case StateQuarantined:
		return next == StateClosed
	default:
		return false
	}
}
