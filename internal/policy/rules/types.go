// Package rules implements the deterministic rule evaluation engine for MCPIDS.
// Rules are the first-line defense evaluated synchronously on every MCP message.
package rules

import (
	"github.com/mcpids/mcpids/pkg/types" //nolint:typecheck
)

// Rule is a single evaluatable security assertion.
// Rules are evaluated in priority order (lowest Priority number = highest priority).
// Within a rule, all Conditions must match (AND semantics).
// AnyOf provides OR-of-AND: if AnyOf is non-empty, any group of conditions within
// it matching is sufficient.
type Rule struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Priority    int               `yaml:"priority" json:"priority"` // lower = evaluated first
	Scope       RuleScope         `yaml:"scope" json:"scope"`
	Conditions  []Condition       `yaml:"conditions" json:"conditions"` // AND semantics
	AnyOf       [][]Condition     `yaml:"any_of,omitempty" json:"any_of,omitempty"` // OR of AND groups
	Action      RuleAction        `yaml:"action" json:"action"`
	Severity    types.Severity    `yaml:"severity" json:"severity"`
	Tags        []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Source identifies where the rule was loaded from: db|yaml|builtin
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
}

// RuleScope controls which MCP messages the rule applies to.
type RuleScope struct {
	// Methods is the set of MCP methods this rule applies to.
	// Empty means all methods.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`

	// Directions is the set of message directions: inbound|outbound|both.
	// Empty means both directions.
	Directions []string `yaml:"directions,omitempty" json:"directions,omitempty"`

	// ServerIDs restricts the rule to specific server UUIDs. Empty = all servers.
	ServerIDs []string `yaml:"server_ids,omitempty" json:"server_ids,omitempty"`

	// TenantIDs restricts the rule to specific tenant UUIDs. Empty = all tenants.
	TenantIDs []string `yaml:"tenant_ids,omitempty" json:"tenant_ids,omitempty"`
}

// Condition is a single evaluatable predicate on the MCP message context.
type Condition struct {
	// Field is a dot-notation path into the message context.
	// Special fields:
	//   tool.name           - tool name (tools/call, tools/list per-tool)
	//   tool.description    - tool description text
	//   tool.input_schema   - tool input schema JSON string
	//   args.<key>          - specific argument from tools/call params
	//   result.text         - concatenated text content from tool call result
	//   resource.uri        - resource URI (resources/read)
	//   prompt.name         - prompt name
	Field string `yaml:"field" json:"field"`

	// Op is the comparison operation.
	Op ConditionOp `yaml:"op" json:"op"`

	// Value is the operand for the condition.
	// Type depends on Op: string for eq/contains/regex, []string for in, etc.
	Value any `yaml:"value" json:"value"`

	// Negate inverts the condition result.
	Negate bool `yaml:"negate,omitempty" json:"negate,omitempty"`
}

// ConditionOp identifies the comparison operation for a Condition.
type ConditionOp string

const (
	// OpEquals checks strict equality.
	OpEquals ConditionOp = "eq"

	// OpContains checks if the field value contains the string value.
	OpContains ConditionOp = "contains"

	// OpRegex checks if the field value matches a single regex pattern.
	OpRegex ConditionOp = "regex"

	// OpRegexAny checks if any element in a repeated field matches any pattern in the value list.
	OpRegexAny ConditionOp = "regex_any"

	// OpIn checks if the field value is in the provided list.
	OpIn ConditionOp = "in"

	// OpExists checks if the field is non-empty/non-null.
	OpExists ConditionOp = "exists"

	// OpGt checks if the numeric field value is greater than the value.
	OpGt ConditionOp = "gt"

	// OpLt checks if the numeric field value is less than the value.
	OpLt ConditionOp = "lt"

	// OpPhraseMatch checks the field value against a named built-in phrase set
	// using Aho-Corasick multi-pattern search.
	// Value must be the name of a phrase set registered in the engine.
	OpPhraseMatch ConditionOp = "phrase_match"

	// OpSecretPattern checks the field value against all built-in secret regexes
	// (API keys, tokens, credentials). Value is ignored.
	OpSecretPattern ConditionOp = "secret_pattern"

	// OpToolNameMatch checks the tool name against an allowlist or denylist.
	// Value is "denylist" or "allowlist" referring to tenant configuration.
	OpToolNameMatch ConditionOp = "tool_name_match"

	// OpSchemaViolation checks if the tool call arguments violate the registered input schema.
	OpSchemaViolation ConditionOp = "schema_violation"
)

// RuleAction describes what happens when a rule matches.
type RuleAction struct {
	// Decision is the enforcement action to apply.
	Decision types.Decision `yaml:"decision" json:"decision"`

	// Redactions describes field-level scrubs when Decision is redact.
	Redactions []types.Redaction `yaml:"redactions,omitempty" json:"redactions,omitempty"`

	// Annotations are key/value pairs attached to the verdict for downstream use.
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// RuleMatch is returned by the engine for each rule that was evaluated.
type RuleMatch struct {
	// Rule is the rule that was evaluated.
	Rule Rule

	// Matched is true if all conditions matched.
	Matched bool

	// Evidence contains human-readable descriptions of which conditions matched and why.
	Evidence []string
}
