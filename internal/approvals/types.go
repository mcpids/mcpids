// Package approvals implements the HITL (human-in-the-loop) approval workflow.
package approvals

import (
	"time"

	"github.com/mcpids/mcpids/pkg/types"
)

// Status represents the lifecycle state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Request is a pending approval held by the gateway.
// The gateway blocks the original MCP message until the request is decided or expires.
type Request struct {
	ID        string        `json:"id"`
	TenantID  string        `json:"tenant_id"`
	AgentID   string        `json:"agent_id"`
	SessionID string        `json:"session_id"`
	ServerID  string        `json:"server_id"`
	ToolName  string        `json:"tool_name,omitempty"`
	// RawPayload is the original MCP JSON-RPC message bytes being held.
	RawPayload []byte        `json:"raw_payload"`
	Verdict    types.Verdict `json:"verdict"`
	Status     Status        `json:"status"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	DecidedBy  string        `json:"decided_by,omitempty"`
	DecidedAt  *time.Time    `json:"decided_at,omitempty"`
	Notes      string        `json:"notes,omitempty"`
}

// Decision is submitted by a human reviewer via the admin API.
type Decision struct {
	RequestID string    `json:"request_id"`
	Status    Status    `json:"status"` // approved or denied
	DecidedBy string    `json:"decided_by"`
	Notes     string    `json:"notes,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
