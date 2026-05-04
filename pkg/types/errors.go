package types

import "errors"

// Sentinel errors used across all MCPIDS components.
// Callers should use errors.Is() for matching.

var (
	// ErrDenied is returned when a policy verdict is deny.
	ErrDenied = errors.New("mcpids: request denied by policy")

	// ErrQuarantined is returned when a session has been quarantined.
	// All subsequent calls on a quarantined session return this error.
	ErrQuarantined = errors.New("mcpids: session quarantined")

	// ErrApprovalTimeout is returned when a HITL approval window expires
	// without a human decision.
	ErrApprovalTimeout = errors.New("mcpids: approval request timed out")

	// ErrApprovalNotFound is returned when an approval request ID is unknown.
	ErrApprovalNotFound = errors.New("mcpids: approval request not found")

	// ErrApprovalDenied is returned when a human explicitly denies an approval.
	ErrApprovalDenied = errors.New("mcpids: approval denied by reviewer")

	// ErrSchemaViolation is returned when tool call arguments fail JSON Schema validation.
	ErrSchemaViolation = errors.New("mcpids: tool arguments fail schema validation")

	// ErrSessionNotFound is returned when a session ID cannot be resolved.
	ErrSessionNotFound = errors.New("mcpids: session not found")

	// ErrServerNotFound is returned when a server ID cannot be resolved.
	ErrServerNotFound = errors.New("mcpids: mcp server not found")

	// ErrToolNotFound is returned when a tool is not in the allowed inventory.
	ErrToolNotFound = errors.New("mcpids: tool not found in allowed inventory")

	// ErrPolicyNotFound is returned when no policy exists for the tenant.
	ErrPolicyNotFound = errors.New("mcpids: policy not found")

	// ErrUnauthorized is returned when a request lacks valid credentials.
	ErrUnauthorized = errors.New("mcpids: unauthorized")

	// ErrForbidden is returned when a principal lacks the required role.
	ErrForbidden = errors.New("mcpids: forbidden")

	// ErrUpstreamUnavailable is returned when the upstream MCP server cannot be reached.
	ErrUpstreamUnavailable = errors.New("mcpids: upstream mcp server unavailable")
)

// PolicyError wraps an error with verdict context for logging and tracing.
type PolicyError struct {
	Verdict *Verdict
	Cause   error
}

func (e *PolicyError) Error() string {
	return "policy error: " + e.Cause.Error()
}

func (e *PolicyError) Unwrap() error {
	return e.Cause
}

// NewPolicyError creates a PolicyError wrapping the given cause and verdict.
func NewPolicyError(v *Verdict, cause error) *PolicyError {
	return &PolicyError{Verdict: v, Cause: cause}
}
