package semantic

import "context"

// Classifier is the pluggable semantic content analysis interface.
// Implementations must be safe for concurrent use.
//
// The system functions correctly with only the built-in stub classifier.
// Plugging in an LLM-based classifier improves detection quality but is optional.
type Classifier interface {
	// Classify synchronously classifies content and returns a result.
	// Implementations MUST respect ctx deadline. The stub completes in < 1ms.
	Classify(ctx context.Context, req ClassifyRequest) (*Result, error)

	// ClassifyAsync submits for asynchronous classification and calls cb when done.
	// Used when the latency budget is tight and blocking is not acceptable.
	// cb may be called from a different goroutine.
	ClassifyAsync(ctx context.Context, req ClassifyRequest, cb func(*Result, error))

	// Name returns the classifier implementation name for logging.
	Name() string
}

// ClassifyRequest is the input to a classifier.
type ClassifyRequest struct {
	// Content is the text to classify.
	Content string

	// ContentType identifies what kind of content this is.
	ContentType ContentType

	// Hints are optional tags to guide classification.
	Hints []string

	// Context is additional information attached to the request for explainability.
	Context map[string]string
}

// Result is the classification output.
type Result struct {
	// Labels is the list of assigned semantic labels.
	Labels []Label

	// RiskScore is a 0.0–1.0 composite risk estimate from the classifier.
	RiskScore float64

	// Confidence is the classifier's overall confidence in its output (0.0–1.0).
	Confidence float64

	// Reasoning is an optional human-readable explanation (from LLM classifiers).
	Reasoning string

	// ModelUsed identifies the model or method that produced this result.
	ModelUsed string
}

// Label is a single semantic classification assigned to the content.
type Label struct {
	Name       string   // e.g. "prompt_injection"
	Confidence float64  // 0.0–1.0
	Evidence   []string // snippets or patterns that triggered this label
}

// HasLabel returns true if the result contains the given label with confidence ≥ minConf.
func (r *Result) HasLabel(name string, minConf float64) bool {
	for _, l := range r.Labels {
		if l.Name == name && l.Confidence >= minConf {
			return true
		}
	}
	return false
}

// LabelNames returns just the label names for use in audit events.
func (r *Result) LabelNames() []string {
	names := make([]string, len(r.Labels))
	for i, l := range r.Labels {
		names[i] = l.Name
	}
	return names
}
