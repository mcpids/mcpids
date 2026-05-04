package policy

import (
	"context"
	"log/slog"

	"github.com/mcpids/mcpids/internal/diff"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/internal/risk"
	"github.com/mcpids/mcpids/internal/semantic"
	"github.com/mcpids/mcpids/pkg/types"
)

// Engine is the central policy decision point.
// It aggregates signals from all evaluation stages into a final Verdict.
type Engine interface {
	// Decide computes a Verdict for the given request context.
	Decide(ctx context.Context, req DecisionRequest) (*types.Verdict, error)
}

// DecisionRequest carries all inputs for a policy decision.
type DecisionRequest struct {
	// Context identifies the tenant, agent, session, server, and method.
	VerdictCtx types.VerdictContext

	// Fields are the extracted message fields for rule evaluation.
	Fields map[string]string

	// RuleMatches are the pre-evaluated rule matches from the rules engine.
	// If nil, the engine evaluates rules internally.
	RuleMatches []rules.RuleMatch

	// DiffSignal is the risk signal from the diff engine (may be nil).
	DiffSignal *diff.Signal

	// GraphSignal is the lateral-movement/call-chain signal from the graph engine.
	GraphSignal *graph.Signal

	// SemanticResult is the classification result (may be nil if async not yet done).
	SemanticResult *semantic.Result

	// IsDryRun, when true, converts all blocking decisions to monitor_only.
	IsDryRun bool

	// IsMonitorOnlyMode is the global pipeline monitor-only override.
	IsMonitorOnlyMode bool
}

// Options configures the policy engine.
type Options struct {
	RulesEngine    rules.Engine
	RiskEngine     risk.Engine
	SemanticEngine semantic.Classifier
}

// engineImpl is the default Engine implementation.
type engineImpl struct {
	rules    rules.Engine
	risk     risk.Engine
	semantic semantic.Classifier
}

// NewEngine creates a policy engine with the given dependencies.
func NewEngine(opts Options) Engine {
	return &engineImpl{
		rules:    opts.RulesEngine,
		risk:     opts.RiskEngine,
		semantic: opts.SemanticEngine,
	}
}

// Decide implements Engine.
func (e *engineImpl) Decide(ctx context.Context, req DecisionRequest) (*types.Verdict, error) {
	// ─── Step 1: Rule evaluation ───────────────────────────────────────────────
	ruleMatches := req.RuleMatches
	if ruleMatches == nil && e.rules != nil {
		evalReq := &rules.EvalRequest{
			Method:    req.VerdictCtx.Method,
			Direction: req.VerdictCtx.Direction,
			TenantID:  req.VerdictCtx.TenantID,
			ServerID:  req.VerdictCtx.ServerID,
			Fields:    req.Fields,
		}
		var err error
		ruleMatches, err = e.rules.Evaluate(ctx, evalReq)
		if err != nil {
			slog.Warn("policy: rule evaluation error", "error", err)
		}
	}

	// ─── Step 2: Risk scoring ─────────────────────────────────────────────────
	signals := risk.Signals{
		RuleMatchCount:   len(ruleMatches),
		ServerTrustScore: 0.5, // default until server trust is loaded
	}

	if req.DiffSignal != nil {
		signals.DiffRisk = req.DiffSignal.RiskContribution
		signals.IsFirstSeen = req.DiffSignal.IsFirstSeen
		signals.IsToolNew = req.DiffSignal.ToolIsNew != ""
	}

	if req.GraphSignal != nil {
		signals.GraphRisk = req.GraphSignal.RiskContribution
	}

	if req.SemanticResult != nil {
		signals.SemanticRisk = req.SemanticResult.RiskScore
	}

	// Find max severity from rule matches.
	for _, m := range ruleMatches {
		if m.Matched {
			if types.SeverityRank[m.Rule.Severity] > types.SeverityRank[signals.MaxRuleSeverity] {
				signals.MaxRuleSeverity = m.Rule.Severity
			}
		}
	}

	riskScore, err := e.risk.Score(ctx, signals)
	if err != nil {
		slog.Warn("policy: risk scoring error", "error", err)
	}
	severity := e.risk.Severity(riskScore)

	// ─── Step 3: Semantic labels ───────────────────────────────────────────────
	var semanticLabels []string
	if req.SemanticResult != nil {
		semanticLabels = req.SemanticResult.LabelNames()
	}

	// ─── Step 4: Build verdict ─────────────────────────────────────────────────
	isDryRun := req.IsDryRun || req.IsMonitorOnlyMode
	verdict := BuildVerdict(ruleMatches, riskScore, severity, semanticLabels, isDryRun)
	if req.GraphSignal != nil && len(req.GraphSignal.SuspiciousPaths) > 0 {
		verdict.Reasons = append(verdict.Reasons, req.GraphSignal.SuspiciousPaths...)
		if verdict.Decision == types.DecisionAllow && req.GraphSignal.RiskContribution >= 0.4 {
			verdict.Decision = types.DecisionMonitorOnly
		}
		if types.SeverityRank[severity] > types.SeverityRank[verdict.Severity] {
			verdict.Severity = severity
		}
	}

	slog.Debug("policy: decision",
		"method", req.VerdictCtx.Method,
		"decision", verdict.Decision,
		"severity", verdict.Severity,
		"risk_score", riskScore,
		"matched_rules", len(ruleMatches),
	)

	return &verdict, nil
}
