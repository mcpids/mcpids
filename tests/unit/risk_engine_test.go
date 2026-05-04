package unit_test

import (
	"context"
	"testing"

	"github.com/mcpids/mcpids/internal/risk"
	"github.com/mcpids/mcpids/pkg/types"
)

func TestRiskEngine_ZeroSignals_LowScore(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)
	score, err := eng.Score(context.Background(), risk.Signals{})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score > 0.3 {
		t.Errorf("score = %f, want <= 0.3 for zero signals", score)
	}
}

func TestRiskEngine_HighRuleMatch_HighScore(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)
	score, err := eng.Score(context.Background(), risk.Signals{
		RuleMatchCount:  5,
		MaxRuleSeverity: types.SeverityCritical,
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score < 0.5 {
		t.Errorf("score = %f, want >= 0.5 for critical rule matches", score)
	}
}

func TestRiskEngine_DiffRisk_ContributesToScore(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)
	baseline, _ := eng.Score(context.Background(), risk.Signals{})
	withDiff, _ := eng.Score(context.Background(), risk.Signals{DiffRisk: 0.8})
	if withDiff <= baseline {
		t.Errorf("diff risk should increase score: baseline=%f, with_diff=%f", baseline, withDiff)
	}
}

func TestRiskEngine_LowTrust_Amplifies(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)

	base, _ := eng.Score(context.Background(), risk.Signals{
		RuleMatchCount:   1,
		MaxRuleSeverity:  types.SeverityMedium,
		ServerTrustScore: 1.0, // full trust
	})
	lowTrust, _ := eng.Score(context.Background(), risk.Signals{
		RuleMatchCount:   1,
		MaxRuleSeverity:  types.SeverityMedium,
		ServerTrustScore: 0.0, // untrusted
	})
	if lowTrust <= base {
		t.Errorf("low trust should amplify score: base=%f, low_trust=%f", base, lowTrust)
	}
}

func TestRiskEngine_FirstSeen_AddsRisk(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)
	base, _ := eng.Score(context.Background(), risk.Signals{})
	firstSeen, _ := eng.Score(context.Background(), risk.Signals{IsFirstSeen: true})
	if firstSeen <= base {
		t.Errorf("first-seen should add risk: base=%f, first_seen=%f", base, firstSeen)
	}
}

func TestRiskEngine_Severity_Banding(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)

	cases := []struct {
		score    float64
		wantMin  types.Severity
	}{
		{0.05, types.SeverityInfo},
		{0.25, types.SeverityLow},
		{0.45, types.SeverityMedium},
		{0.70, types.SeverityHigh},
		{0.90, types.SeverityCritical},
	}

	for _, tc := range cases {
		sev := eng.Severity(tc.score)
		if sev != tc.wantMin {
			t.Errorf("Severity(%f) = %q, want %q", tc.score, sev, tc.wantMin)
		}
	}
}

func TestRiskEngine_ScoreNeverExceedsOne(t *testing.T) {
	eng := risk.NewEngine(risk.DefaultWeights)
	score, err := eng.Score(context.Background(), risk.Signals{
		RuleMatchCount:   100,
		MaxRuleSeverity:  types.SeverityCritical,
		SemanticRisk:     1.0,
		DiffRisk:         1.0,
		GraphRisk:        1.0,
		IsFirstSeen:      true,
		IsToolNew:        true,
		ServerTrustScore: 0.0,
		DataSensitivity:  1.0,
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score > 1.0 {
		t.Errorf("score = %f, must not exceed 1.0", score)
	}
}
