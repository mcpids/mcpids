package rules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/mcpids/mcpids/pkg/types"
)

// Engine evaluates rules against MCP message context.
type Engine interface {
	// Evaluate applies all matching rules to the given context.
	// Returns matches in order of evaluation (highest priority first).
	// Multiple monitor_only rules are all returned; first deny/quarantine short-circuits.
	Evaluate(ctx context.Context, req *EvalRequest) ([]RuleMatch, error)

	// Reload hot-reloads rules from YAML files and the in-memory store.
	// Safe to call concurrently; uses a write lock for the swap.
	Reload(ctx context.Context) error

	// RuleCount returns the current number of loaded rules (for metrics).
	RuleCount() int
}

// EvalRequest carries all context an interceptor has available for rule evaluation.
type EvalRequest struct {
	// Method is the MCP method being evaluated (e.g. "tools/call").
	Method string

	// Direction is inbound|outbound.
	Direction string

	// TenantID and ServerID are used for scope matching.
	TenantID string
	ServerID string

	// Fields are the extracted string values keyed by field name.
	// Populated by the pipeline before calling Evaluate.
	Fields map[string]string
}

// engineImpl is the default Engine implementation.
type engineImpl struct {
	mu              sync.RWMutex
	rules           []Rule           // sorted by Priority ASC (lower = evaluated first)
	phraseSets      map[string][]string // name → phrases (lowercase)
	compiledRegexes map[string]*regexp.Regexp
	yamlPaths       []string
	store           Store
}

// NewEngine creates an Engine, loading rules from the provided YAML files.
// Built-in phrase sets are registered automatically.
func NewEngine(ctx context.Context, yamlPaths []string) (Engine, error) {
	return NewEngineWithStore(ctx, yamlPaths, nil)
}

// NewEngineWithStore creates an Engine backed by YAML, PostgreSQL, and built-ins.
func NewEngineWithStore(ctx context.Context, yamlPaths []string, store Store) (Engine, error) {
	e := &engineImpl{
		phraseSets:      make(map[string][]string),
		compiledRegexes: make(map[string]*regexp.Regexp),
		yamlPaths:       yamlPaths,
		store:           store,
	}

	// Register built-in phrase sets.
	e.registerPhraseSet("suspicious_tool_phrases", SuspiciousToolPhrases)
	e.registerPhraseSet("exfiltration_phrases", ExfiltrationPhrases)
	e.registerPhraseSet("hidden_instruction_phrases", HiddenInstructionPhrases)

	if err := e.Reload(ctx); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *engineImpl) registerPhraseSet(name string, phrases []string) {
	lower := make([]string, len(phrases))
	for i, p := range phrases {
		lower[i] = strings.ToLower(p)
	}
	e.phraseSets[name] = lower
}

// Evaluate implements Engine.
func (e *engineImpl) Evaluate(ctx context.Context, req *EvalRequest) ([]RuleMatch, error) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	var matches []RuleMatch

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !e.scopeMatches(rule.Scope, req) {
			continue
		}

		match := e.evalRule(rule, req)
		if match.Matched {
			matches = append(matches, match)
			// Short-circuit on terminal decisions.
			if rule.Action.Decision == types.DecisionDeny || rule.Action.Decision == types.DecisionQuarantine {
				break
			}
		}
	}

	return matches, nil
}

// evalRule evaluates a single rule against the request fields.
func (e *engineImpl) evalRule(rule Rule, req *EvalRequest) RuleMatch {
	match := RuleMatch{Rule: rule}

	// Evaluate Conditions (AND).
	if len(rule.Conditions) > 0 {
		allMet := true
		for _, cond := range rule.Conditions {
			fieldVal := req.Fields[cond.Field]
			result := EvaluateCondition(cond, fieldVal, e)
			if !result.Matched {
				allMet = false
				break
			}
			if result.Evidence != "" {
				match.Evidence = append(match.Evidence, result.Evidence)
			}
		}
		if allMet {
			match.Matched = true
		}
		return match
	}

	// Evaluate AnyOf (OR of AND groups).
	if len(rule.AnyOf) > 0 {
		for _, group := range rule.AnyOf {
			groupMet := true
			var groupEvidence []string
			for _, cond := range group {
				fieldVal := req.Fields[cond.Field]
				result := EvaluateCondition(cond, fieldVal, e)
				if !result.Matched {
					groupMet = false
					break
				}
				if result.Evidence != "" {
					groupEvidence = append(groupEvidence, result.Evidence)
				}
			}
			if groupMet {
				match.Matched = true
				match.Evidence = append(match.Evidence, groupEvidence...)
				return match
			}
		}
		return match
	}

	// A rule with no conditions always matches (useful for scope-only rules).
	match.Matched = true
	return match
}

// scopeMatches returns true if the request is in scope for the given rule.
func (e *engineImpl) scopeMatches(scope RuleScope, req *EvalRequest) bool {
	if len(scope.Methods) > 0 {
		found := false
		for _, m := range scope.Methods {
			if m == req.Method {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(scope.Directions) > 0 {
		found := false
		for _, d := range scope.Directions {
			if d == req.Direction || d == "both" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(scope.TenantIDs) > 0 {
		found := false
		for _, tid := range scope.TenantIDs {
			if tid == req.TenantID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(scope.ServerIDs) > 0 {
		found := false
		for _, sid := range scope.ServerIDs {
			if sid == req.ServerID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Reload implements Engine.
func (e *engineImpl) Reload(ctx context.Context) error {
	var loaded []Rule
	byID := make(map[string]Rule)

	if e.store != nil {
		dbRules, err := e.store.LoadRules(ctx)
		if err != nil {
			return err
		}
		for _, rule := range dbRules {
			byID[rule.ID] = rule
		}
	}

	for _, path := range e.yamlPaths {
		rules, err := loadYAMLRules(path)
		if err != nil {
			slog.Warn("rules: failed to load YAML file, skipping",
				"path", path, "error", err)
			continue
		}
		for _, rule := range rules {
			byID[rule.ID] = rule
		}
	}

	// Append built-in rules only when no DB/YAML rule reuses the same ID.
	for _, rule := range builtinRules() {
		if _, exists := byID[rule.ID]; !exists {
			byID[rule.ID] = rule
		}
	}

	loaded = make([]Rule, 0, len(byID))
	for _, rule := range byID {
		loaded = append(loaded, rule)
	}

	// Sort by Priority ascending (lower = higher priority).
	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].Priority < loaded[j].Priority
	})

	e.mu.Lock()
	e.rules = loaded
	e.mu.Unlock()

	slog.Info("rules: loaded", "count", len(loaded))
	return nil
}

// RuleCount implements Engine.
func (e *engineImpl) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// ─── YAML loading ─────────────────────────────────────────────────────────────

type yamlRuleFile struct {
	Rules []Rule `yaml:"rules"`
}

func loadYAMLRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	var f yamlRuleFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}

	for i := range f.Rules {
		f.Rules[i].Source = "yaml"
		if f.Rules[i].ID == "" {
			return nil, fmt.Errorf("rule at index %d in %q has no id", i, path)
		}
	}

	return f.Rules, nil
}

// builtinRules returns the hard-coded default rules that are always loaded.
// These provide baseline protection even without any YAML or DB rules.
func builtinRules() []Rule {
	secretRedactions := []types.Redaction{
		{FieldPath: "result.text", Pattern: `AKIA[0-9A-Z]{16}`, Replacement: "[AWS_KEY_REDACTED]"},
		{FieldPath: "result.text", Pattern: `ghp_[A-Za-z0-9]{36}`, Replacement: "[GITHUB_PAT_REDACTED]"},
		{FieldPath: "result.text", Pattern: `sk-[A-Za-z0-9]{48,}`, Replacement: "[OPENAI_KEY_REDACTED]"},
		{FieldPath: "result.text", Pattern: `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`, Replacement: "[JWT_REDACTED]"},
	}

	return []Rule{
		{
			ID:          "builtin-001-tool-injection-phrase",
			Name:        "Block tool descriptions with injection phrases",
			Description: "Hides tools whose description contains known prompt injection phrases",
			Enabled:     true,
			Priority:    10,
			Source:      "builtin",
			Scope: RuleScope{
				Methods:    []string{"tools/list"},
				Directions: []string{"outbound"},
			},
			Conditions: []Condition{
				{Field: "tool.description", Op: OpPhraseMatch, Value: "suspicious_tool_phrases"},
			},
			Action:   RuleAction{Decision: types.DecisionHide},
			Severity: types.SeverityHigh,
			Tags:     []string{"tool-poisoning", "prompt-injection"},
		},
		{
			ID:          "builtin-002-tool-exfil-phrase",
			Name:        "Block tool descriptions with exfiltration phrases",
			Description: "Denies tool calls where the tool description instructs data exfiltration",
			Enabled:     true,
			Priority:    15,
			Source:      "builtin",
			Scope: RuleScope{
				Methods:    []string{"tools/list"},
				Directions: []string{"outbound"},
			},
			Conditions: []Condition{
				{Field: "tool.description", Op: OpPhraseMatch, Value: "exfiltration_phrases"},
			},
			Action:   RuleAction{Decision: types.DecisionDeny},
			Severity: types.SeverityHigh,
			Tags:     []string{"exfiltration", "tool-poisoning"},
		},
		{
			ID:          "builtin-003-response-secret",
			Name:        "Redact secrets in tool call responses",
			Description: "Redacts API keys, tokens, and credentials found in tool outputs",
			Enabled:     true,
			Priority:    20,
			Source:      "builtin",
			Scope: RuleScope{
				Methods:    []string{"tools/call"},
				Directions: []string{"outbound"},
			},
			Conditions: []Condition{
				{Field: "result.text", Op: OpSecretPattern},
			},
			Action: RuleAction{
				Decision:   types.DecisionRedact,
				Redactions: secretRedactions,
			},
			Severity: types.SeverityCritical,
			Tags:     []string{"secret-leak", "data-protection"},
		},
		{
			ID:          "builtin-004-response-injection",
			Name:        "Detect hidden instructions in tool outputs",
			Description: "Flags tool responses containing hidden instruction phrases (indirect prompt injection)",
			Enabled:     true,
			Priority:    25,
			Source:      "builtin",
			Scope: RuleScope{
				Methods:    []string{"tools/call"},
				Directions: []string{"outbound"},
			},
			Conditions: []Condition{
				{Field: "result.text", Op: OpPhraseMatch, Value: "hidden_instruction_phrases"},
			},
			Action:   RuleAction{Decision: types.DecisionMonitorOnly},
			Severity: types.SeverityHigh,
			Tags:     []string{"prompt-injection", "indirect-injection"},
		},
		{
			ID:          "builtin-005-tool-schema-violation",
			Name:        "Deny tool calls with invalid arguments",
			Description: "Blocks tools/call requests whose arguments violate the tool's input schema",
			Enabled:     true,
			Priority:    12,
			Source:      "builtin",
			Scope: RuleScope{
				Methods:    []string{"tools/call"},
				Directions: []string{"inbound"},
			},
			Conditions: []Condition{
				{Field: "tool.schema_violation", Op: OpSchemaViolation},
			},
			Action:   RuleAction{Decision: types.DecisionDeny},
			Severity: types.SeverityHigh,
			Tags:     []string{"schema-validation", "policy"},
		},
	}
}
