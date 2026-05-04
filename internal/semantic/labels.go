// Package semantic provides the pluggable semantic content classification interface.
// The stub classifier runs locally with no external dependencies.
// Production implementations can plug in LLM-based classifiers via the Classifier interface.
package semantic

// Standard semantic label taxonomy used across all classifiers.
const (
	LabelPromptInjection   = "prompt_injection"
	LabelIndirectInjection = "indirect_injection"
	LabelCredentialLeak    = "credential_leak"
	LabelPIIEmail          = "pii_email"
	LabelPIISSN            = "pii_ssn"
	LabelPIICreditCard     = "pii_credit_card"
	LabelPIIPhone          = "pii_phone"
	LabelDataExfiltration  = "data_exfiltration"
	LabelToolPoisoning     = "tool_poisoning"
	LabelSSRF              = "ssrf_attempt"
	LabelCommandInjection  = "command_injection"
	LabelPrivEscalation    = "privilege_escalation"
	LabelShadowTool        = "shadow_tool"
	LabelSecrecyLanguage   = "secrecy_language"
	LabelAuthorityOverride = "authority_override"
)

// ContentType identifies the kind of content being classified.
type ContentType string

const (
	ContentTypeText            ContentType = "text"
	ContentTypeToolDescription ContentType = "tool_description"
	ContentTypeToolOutput      ContentType = "tool_output"
	ContentTypePrompt          ContentType = "prompt"
)
