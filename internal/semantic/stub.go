package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/mcpids/mcpids/internal/policy/rules"
)

// StubClassifier is the built-in local classifier.
// It uses Aho-Corasick phrase matching and regex patterns compiled from the rules engine
// built-ins. No external service is required.
//
// Quality note: The stub is regex/phrase-based and will not catch novel phrasings.
// It provides adequate baseline detection for known patterns.
type StubClassifier struct{}

// NewStubClassifier creates a new stub classifier.
func NewStubClassifier() Classifier {
	return &StubClassifier{}
}

// Name implements Classifier.
func (s *StubClassifier) Name() string { return "stub" }

// Classify implements Classifier.
func (s *StubClassifier) Classify(_ context.Context, req ClassifyRequest) (*Result, error) {
	result := &Result{
		ModelUsed:  "stub",
		Confidence: 0.7, // stub confidence is fixed at 0.7
	}

	lower := strings.ToLower(req.Content)

	// ─── Tool description / prompt injection detection ─────────────────────────
	if req.ContentType == ContentTypeToolDescription || req.ContentType == ContentTypePrompt {
		for _, phrase := range rules.SuspiciousToolPhrases {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				result.Labels = append(result.Labels, Label{
					Name:       LabelPromptInjection,
					Confidence: 0.85,
					Evidence:   []string{"phrase: " + phrase},
				})
				result.RiskScore = max(result.RiskScore, 0.8)
				break
			}
		}

		for _, phrase := range rules.ExfiltrationPhrases {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				result.Labels = append(result.Labels, Label{
					Name:       LabelDataExfiltration,
					Confidence: 0.80,
					Evidence:   []string{"phrase: " + phrase},
				})
				result.RiskScore = max(result.RiskScore, 0.75)
				break
			}
		}

		// Secrecy/authority language
		secrecyPhrases := []string{"do not reveal", "keep secret", "without telling", "without disclosing"}
		for _, p := range secrecyPhrases {
			if strings.Contains(lower, p) {
				result.Labels = append(result.Labels, Label{
					Name:       LabelSecrecyLanguage,
					Confidence: 0.75,
					Evidence:   []string{"phrase: " + p},
				})
				result.RiskScore = max(result.RiskScore, 0.65)
				break
			}
		}
	}

	// ─── Tool output / indirect injection detection ────────────────────────────
	if req.ContentType == ContentTypeToolOutput || req.ContentType == ContentTypeText {
		for _, phrase := range rules.HiddenInstructionPhrases {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				result.Labels = append(result.Labels, Label{
					Name:       LabelIndirectInjection,
					Confidence: 0.80,
					Evidence:   []string{"phrase: " + phrase},
				})
				result.RiskScore = max(result.RiskScore, 0.75)
				break
			}
		}

		// Credential detection.
		for _, sp := range rules.SecretPatterns {
			if sp.Pattern.MatchString(req.Content) {
				result.Labels = append(result.Labels, Label{
					Name:       LabelCredentialLeak,
					Confidence: 0.90,
					Evidence:   []string{"pattern: " + sp.Name},
				})
				result.RiskScore = max(result.RiskScore, 0.90)
				break
			}
		}

		// PII detection.
		if emailRegex.MatchString(req.Content) && req.ContentType == ContentTypeToolOutput {
			result.Labels = append(result.Labels, Label{
				Name:       LabelPIIEmail,
				Confidence: 0.70,
				Evidence:   []string{"email address detected"},
			})
			result.RiskScore = max(result.RiskScore, 0.4)
		}
	}

	return result, nil
}

// ClassifyAsync implements Classifier.
// The stub runs synchronously and immediately calls cb.
func (s *StubClassifier) ClassifyAsync(ctx context.Context, req ClassifyRequest, cb func(*Result, error)) {
	result, err := s.Classify(ctx, req)
	cb(result, err)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
