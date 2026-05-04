// Package types defines shared domain types used across all MCPIDS components.
package types

// Decision is the enforcement action the policy engine returns.
type Decision string

const (
	// DecisionAllow passes the MCP message through unchanged.
	DecisionAllow Decision = "allow"

	// DecisionDeny blocks the MCP message and returns an error to the caller.
	DecisionDeny Decision = "deny"

	// DecisionHide removes the item from discovery results (tools/list, prompts/list, resources/list).
	// The upstream server still has the tool; the agent/model never learns it exists.
	DecisionHide Decision = "hide"

	// DecisionRedact forwards the response but scrubs matched content in-place.
	DecisionRedact Decision = "redact"

	// DecisionQuarantine freezes the entire session. All subsequent calls are denied.
	// An incident is automatically created.
	DecisionQuarantine Decision = "quarantine"

	// DecisionRequireApproval holds the message pending a human decision.
	// The gateway blocks until approved, denied, or the approval window expires.
	DecisionRequireApproval Decision = "require_approval"

	// DecisionMonitorOnly passes the message but records a detection event.
	// Used for dry-run / rollout mode.
	DecisionMonitorOnly Decision = "monitor_only"
)

// Severity indicates detection severity, used for alerting and risk banding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank maps Severity to a numeric rank for comparison.
var SeverityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Redaction describes a single field to scrub in a response payload.
type Redaction struct {
	// FieldPath is a dot-notation JSON path, e.g. "result.content[0].text"
	FieldPath   string `json:"field_path"`
	// Pattern is the regex to match within the field value.
	Pattern     string `json:"pattern"`
	// Replacement is what to substitute for matched content.
	Replacement string `json:"replacement"`
}

// Verdict is the authoritative decision produced by the policy engine for a single
// MCP message. It is immutable once produced. All enforcement logic reads from this struct.
type Verdict struct {
	// Decision is the enforcement action to take.
	Decision Decision `json:"decision"`

	// Severity of the highest-severity signal that contributed to this verdict.
	Severity Severity `json:"severity"`

	// Reasons contains human-readable explanations, one per contributing signal.
	Reasons []string `json:"reasons,omitempty"`

	// MatchedRules contains the rule IDs that fired during evaluation.
	MatchedRules []string `json:"matched_rules,omitempty"`

	// SemanticLabels contains labels assigned by the semantic classifier.
	SemanticLabels []string `json:"semantic_labels,omitempty"`

	// Confidence is a 0.0–1.0 score expressing verdict certainty.
	// Low confidence may trigger require_approval even when a rule matches.
	Confidence float64 `json:"confidence"`

	// RequiresApproval is set when the verdict itself is allow/monitor but
	// a policy rule demands HITL confirmation before forwarding.
	RequiresApproval bool `json:"requires_approval,omitempty"`

	// Redactions describes field-level scrubs to apply when Decision == DecisionRedact.
	Redactions []Redaction `json:"redactions,omitempty"`

	// IncidentCandidate flags this verdict as suitable for automatic incident creation.
	IncidentCandidate bool `json:"incident_candidate,omitempty"`

	// EvidenceRefs contains audit event IDs that support this verdict.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`

	// RiskScore is the normalized 0.0–1.0 risk score that contributed to this verdict.
	RiskScore float64 `json:"risk_score,omitempty"`
}

// IsBlocking returns true when the verdict prevents the MCP message from proceeding
// without additional action.
func (v *Verdict) IsBlocking() bool {
	return v.Decision == DecisionDeny ||
		v.Decision == DecisionQuarantine ||
		v.Decision == DecisionRequireApproval
}

// IsTerminal returns true when the verdict permanently ends the session.
func (v *Verdict) IsTerminal() bool {
	return v.Decision == DecisionQuarantine
}

// VerdictContext carries the evaluation context passed to every interceptor.
// It is read-only during evaluation.
type VerdictContext struct {
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id"`
	ServerID  string `json:"server_id"`
	Method    string `json:"method"` // MCP method name
	Direction string `json:"direction"` // inbound|outbound
}

// DecisionPrecedence defines the ordering of decisions when merging multiple partial verdicts.
// Higher index = higher precedence (wins).
var DecisionPrecedence = map[Decision]int{
	DecisionAllow:           0,
	DecisionMonitorOnly:     1,
	DecisionHide:            2,
	DecisionRedact:          3,
	DecisionRequireApproval: 4,
	DecisionDeny:            5,
	DecisionQuarantine:      6,
}

// MergeDecision returns the higher-precedence decision.
func MergeDecision(a, b Decision) Decision {
	if DecisionPrecedence[b] > DecisionPrecedence[a] {
		return b
	}
	return a
}
