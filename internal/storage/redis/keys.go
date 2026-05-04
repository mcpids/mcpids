// Package redis provides the Redis client and key namespace definitions for MCPIDS.
package redis

import "fmt"

// Key namespace prefixes. All MCPIDS Redis keys follow the pattern:
//
//	mcpids:{namespace}:{identifier}
const (
	nsSession  = "mcpids:session"
	nsPolicy   = "mcpids:policy"
	nsApproval = "mcpids:approval"
	nsRateLimit = "mcpids:ratelimit"
	nsApprovalDecision = "mcpids:approval:decision"
)

// SessionKey returns the Redis key for a session record.
//
//	mcpids:session:{sessionID}
func SessionKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", nsSession, sessionID)
}

// SessionExternalKey returns the Redis key for looking up a session by external ID.
//
//	mcpids:session:ext:{externalID}
func SessionExternalKey(externalID string) string {
	return fmt.Sprintf("%s:ext:%s", nsSession, externalID)
}

// PolicyKey returns the Redis key for the cached policy snapshot for a tenant.
//
//	mcpids:policy:{tenantID}
func PolicyKey(tenantID string) string {
	return fmt.Sprintf("%s:%s", nsPolicy, tenantID)
}

// PolicyVersionKey returns the Redis key for the policy version number.
//
//	mcpids:policy:{tenantID}:version
func PolicyVersionKey(tenantID string) string {
	return fmt.Sprintf("%s:%s:version", nsPolicy, tenantID)
}

// ApprovalKey returns the Redis key for a pending approval request.
//
//	mcpids:approval:{requestID}
func ApprovalKey(requestID string) string {
	return fmt.Sprintf("%s:%s", nsApproval, requestID)
}

// ApprovalDecisionChannel returns the Redis pub/sub channel for approval decisions.
// The gateway subscribes to this channel and unblocks when a decision is published.
//
//	mcpids:approval:decision:{requestID}
func ApprovalDecisionChannel(requestID string) string {
	return fmt.Sprintf("%s:%s", nsApprovalDecision, requestID)
}

// RateLimitKey returns the Redis key for rate-limiting a tenant's tool calls.
//
//	mcpids:ratelimit:{tenantID}:{windowKey}
func RateLimitKey(tenantID, windowKey string) string {
	return fmt.Sprintf("%s:%s:%s", nsRateLimit, tenantID, windowKey)
}
