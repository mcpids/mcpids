// Package risk implements the composite risk scoring engine.
// It aggregates signals from rules, semantic classification, diff, and graph engines
// into a normalized 0.0–1.0 risk score.
package risk

import (
	"context"
	"math"

	"github.com/mcpids/mcpids/pkg/types"
)

// Engine computes composite risk scores.
type Engine interface {
	// Score aggregates signals into a normalized [0.0, 1.0] risk score.
	Score(ctx context.Context, signals Signals) (float64, error)

	// Severity converts a raw risk score to a Severity band.
	Severity(score float64) types.Severity
}

// Signals carries all available risk inputs for a single MCP message evaluation.
type Signals struct {
	// RuleMatchCount is the number of rules that matched.
	RuleMatchCount int

	// MaxRuleSeverity is the highest severity among matched rules.
	MaxRuleSeverity types.Severity

	// SemanticRisk is the risk score from the semantic classifier (0.0–1.0).
	// May be 0.0 if semantic classification is disabled or not yet complete.
	SemanticRisk float64

	// DiffRisk is the risk contribution from the diff engine (0.0–1.0).
	DiffRisk float64

	// GraphRisk is the risk contribution from the graph engine (0.0–1.0).
	GraphRisk float64

	// IsFirstSeen is true when the server has never been seen before.
	IsFirstSeen bool

	// IsToolNew is true when this specific tool has never been called before.
	IsToolNew bool

	// CallFrequency is the tool call rate in calls/minute.
	// High frequency increases risk.
	CallFrequency float64

	// ServerTrustScore is the server's stored trust score (0.0=untrusted, 1.0=trusted).
	// Low trust multiplies other risk signals.
	ServerTrustScore float64

	// DataSensitivity is a 0.0–1.0 score indicating how sensitive the data is.
	DataSensitivity float64
}

// Weights controls the relative contribution of each signal to the final score.
type Weights struct {
	Rule          float64 `yaml:"rule"`
	Semantic      float64 `yaml:"semantic"`
	Diff          float64 `yaml:"diff"`
	Graph         float64 `yaml:"graph"`
	FirstSeen     float64 `yaml:"first_seen"`
	CallFrequency float64 `yaml:"call_frequency"`
}

// DefaultWeights are the production-tuned default weights.
var DefaultWeights = Weights{
	Rule:          0.40,
	Semantic:      0.20,
	Diff:          0.25,
	Graph:         0.10,
	FirstSeen:     0.05,
	CallFrequency: 0.00, // disabled by default
}

// engineImpl is the default Engine implementation.
type engineImpl struct {
	weights Weights
}

// NewEngine creates a new risk engine with the given weights.
// Pass DefaultWeights unless you have specific tuning requirements.
func NewEngine(weights Weights) Engine {
	return &engineImpl{weights: weights}
}

// Score implements Engine.
// The scoring model is a weighted sum of normalized inputs, passed through a
// sigmoid function to produce a smooth [0.0, 1.0] output.
func (e *engineImpl) Score(ctx context.Context, signals Signals) (float64, error) {
	var rawScore float64

	// Rule contribution: severity-weighted rule count.
	var ruleScore float64
	if signals.RuleMatchCount > 0 {
		severityWeight := severityToFloat(signals.MaxRuleSeverity)
		ruleScore = math.Min(float64(signals.RuleMatchCount)*severityWeight*0.3, 1.0)
	}
	rawScore += ruleScore * e.weights.Rule

	// Semantic contribution.
	rawScore += signals.SemanticRisk * e.weights.Semantic

	// Diff contribution.
	rawScore += signals.DiffRisk * e.weights.Diff

	// Graph contribution.
	rawScore += signals.GraphRisk * e.weights.Graph

	// First-seen bonus (adds flat risk for novel servers/tools).
	if signals.IsFirstSeen || signals.IsToolNew {
		rawScore += e.weights.FirstSeen
	}

	// Trust score multiplier: low trust amplifies risk.
	// Trust 1.0 = no amplification; Trust 0.0 = double.
	if signals.ServerTrustScore < 1.0 {
		trustMultiplier := 1.0 + (1.0-signals.ServerTrustScore)*0.5
		rawScore *= trustMultiplier
	}

	// Data sensitivity multiplier.
	if signals.DataSensitivity > 0 {
		rawScore += signals.DataSensitivity * 0.1
	}

	// Normalize through a zero-anchored sigmoid so no signals map to 0.0 instead of 0.5.
	score := 2*sigmoid(rawScore*3.0) - 1
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return math.Round(score*100) / 100, nil
}

// Severity implements Engine.
func (e *engineImpl) Severity(score float64) types.Severity {
	switch {
	case score >= 0.85:
		return types.SeverityCritical
	case score >= 0.65:
		return types.SeverityHigh
	case score >= 0.40:
		return types.SeverityMedium
	case score >= 0.20:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// sigmoid maps any real number to (0, 1).
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// severityToFloat converts a severity level to a float weight for scoring.
func severityToFloat(s types.Severity) float64 {
	switch s {
	case types.SeverityCritical:
		return 1.0
	case types.SeverityHigh:
		return 0.8
	case types.SeverityMedium:
		return 0.5
	case types.SeverityLow:
		return 0.3
	default:
		return 0.1
	}
}
