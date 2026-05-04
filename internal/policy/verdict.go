// Package policy implements the central policy decision point for MCPIDS.
package policy

import (
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/pkg/types"
)

// BuildVerdict constructs a Verdict by merging signals from all evaluation stages.
// Precedence (highest wins): quarantine > deny > require_approval > redact > hide > monitor_only > allow
func BuildVerdict(
	ruleMatches []rules.RuleMatch,
	riskScore float64,
	severity types.Severity,
	semanticLabels []string,
	isDryRun bool,
) types.Verdict {
	v := types.Verdict{
		Decision:       types.DecisionAllow,
		Severity:       types.SeverityInfo,
		Confidence:     1.0,
		RiskScore:      riskScore,
		SemanticLabels: semanticLabels,
	}

	for _, m := range ruleMatches {
		if !m.Matched {
			continue
		}

		v.MatchedRules = append(v.MatchedRules, m.Rule.ID)
		v.Reasons = append(v.Reasons, m.Rule.Name+": "+joinEvidence(m.Evidence))

		// Apply severity escalation.
		if types.SeverityRank[m.Rule.Severity] > types.SeverityRank[v.Severity] {
			v.Severity = m.Rule.Severity
		}

		// Apply decision precedence.
		v.Decision = types.MergeDecision(v.Decision, m.Rule.Action.Decision)

		// Accumulate redactions.
		v.Redactions = append(v.Redactions, m.Rule.Action.Redactions...)

		// Approval required if rule demands it.
		if m.Rule.Action.Decision == types.DecisionRequireApproval {
			v.RequiresApproval = true
		}
	}

	// Apply risk-score-based severity if no rules matched.
	if len(ruleMatches) == 0 && severity != types.SeverityInfo {
		v.Severity = severity
	}

	// High-severity detections are incident candidates.
	if types.SeverityRank[v.Severity] >= types.SeverityRank[types.SeverityHigh] {
		v.IncidentCandidate = true
	}

	// Dry-run mode overrides all blocking decisions to monitor_only.
	if isDryRun && v.Decision != types.DecisionAllow {
		original := v.Decision
		v.Decision = types.DecisionMonitorOnly
		v.Reasons = append(v.Reasons, "dry-run mode: would have "+string(original))
	}

	return v
}

// MergePartialVerdicts merges a slice of partial verdicts (one per tool in tools/list)
// into a single verdict for the aggregate operation.
func MergePartialVerdicts(verdicts []types.Verdict) types.Verdict {
	if len(verdicts) == 0 {
		return types.Verdict{Decision: types.DecisionAllow, Severity: types.SeverityInfo}
	}

	merged := verdicts[0]
	for _, v := range verdicts[1:] {
		merged.Decision = types.MergeDecision(merged.Decision, v.Decision)
		if types.SeverityRank[v.Severity] > types.SeverityRank[merged.Severity] {
			merged.Severity = v.Severity
		}
		merged.Reasons = append(merged.Reasons, v.Reasons...)
		merged.MatchedRules = append(merged.MatchedRules, v.MatchedRules...)
		merged.SemanticLabels = append(merged.SemanticLabels, v.SemanticLabels...)
		merged.Redactions = append(merged.Redactions, v.Redactions...)
		if v.RequiresApproval {
			merged.RequiresApproval = true
		}
		if v.IncidentCandidate {
			merged.IncidentCandidate = true
		}
		if v.RiskScore > merged.RiskScore {
			merged.RiskScore = v.RiskScore
		}
	}
	return merged
}

func joinEvidence(evidence []string) string {
	result := ""
	for i, e := range evidence {
		if i > 0 {
			result += "; "
		}
		result += e
	}
	return result
}
