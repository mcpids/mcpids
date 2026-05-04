package unit_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/pkg/types"
)

// threatScenario is the JSON fixture schema for rules-engine-testable scenarios.
type threatScenario struct {
	Scenario        string            `json:"scenario"`
	Method          string            `json:"method"`
	Direction       string            `json:"direction"`
	Fields          map[string]string `json:"fields"`
	ExpectedVerdict string            `json:"expected_verdict"`
	ExpectedRule    string            `json:"expected_rule"`
}

// TestThreatScenarios_RulesEngine validates scenarios that are detectable purely
// by the rules engine (scenarios 01, 02, 03). Others rely on diff/graph signals
// and are covered by unit tests for those engines.
func TestThreatScenarios_RulesEngine(t *testing.T) {
	// Only test scenarios with populated "fields" (rules-engine testable).
	rulesTestable := []string{
		"01_ignore_prev_instructions.json",
		"02_secret_exfil_description.json",
		"03_hidden_instruction_in_output.json",
	}

	fixtureDir := filepath.Join("..", "fixtures", "threat_scenarios")
	eng, err := rules.NewEngine(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for _, fname := range rulesTestable {
		fname := fname
		t.Run(fname, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(fixtureDir, fname))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			var sc threatScenario
			if err := json.Unmarshal(data, &sc); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}

			if sc.Fields == nil {
				t.Skip("no fields in fixture, not rules-testable")
			}

			req := &rules.EvalRequest{
				Method:    sc.Method,
				Direction: sc.Direction,
				TenantID:  "t1",
				ServerID:  "srv-1",
				Fields:    sc.Fields,
			}

			matches, err := eng.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			// Map expected verdict string to types.Decision.
			want := types.Decision(sc.ExpectedVerdict)
			found := false
			for _, m := range matches {
				if m.Rule.Action.Decision == want {
					found = true
				}
				// Check specific expected rule if set.
				if sc.ExpectedRule != "" && m.Rule.ID == sc.ExpectedRule {
					found = true
				}
			}

			if !found {
				t.Errorf("scenario %q: expected verdict %q (or rule %q), got matches: %+v",
					sc.Scenario, want, sc.ExpectedRule, matches)
			}
		})
	}
}
