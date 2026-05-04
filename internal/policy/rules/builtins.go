package rules

import "regexp"

// ─── Suspicious Tool Description Phrases ─────────────────────────────────────
// These phrases in tool descriptions indicate potential tool poisoning -
// an attempt to override model instructions via injected tool metadata.

// SuspiciousToolPhrases is the canonical built-in phrase set for tool poisoning detection.
// Matched against: tool.description (tools/list responses).
var SuspiciousToolPhrases = []string{
	// Instruction override patterns
	"ignore previous instructions",
	"ignore all previous",
	"disregard previous",
	"disregard all previous",
	"forget previous instructions",
	"forget all instructions",
	"ignore the above",
	"ignore above instructions",
	"override previous",
	"override all instructions",
	"bypass previous",
	"skip previous instructions",

	// Authority / role claiming patterns
	"act as",
	"pretend to be",
	"you are now",
	"from now on you",
	"your new role",
	"your actual instructions",
	"your true instructions",
	"your real instructions",

	// System prompt manipulation
	"disregard system prompt",
	"ignore system prompt",
	"your system prompt is",
	"the real system prompt",
	"overwrite system",

	// Secrecy / non-disclosure patterns (tool-poisoning indicator)
	"do not reveal",
	"do not disclose",
	"do not tell the user",
	"do not mention this",
	"keep this secret",
	"hide this from",
	"without the user knowing",
	"without telling the user",
	"silently",
	"covertly",
}

// ExfiltrationPhrases matches tool descriptions that attempt to instruct
// silent data exfiltration to external destinations.
var ExfiltrationPhrases = []string{
	"send to",
	"upload to",
	"post to",
	"exfiltrate",
	"leak to",
	"transmit to",
	"forward to",
	"relay to",
	"copy to",
	"backup to",
	"sync to external",
	"push to remote",
	"without alerting",
	"without logging",
	"without notification",
}

// HiddenInstructionPhrases are phrases found in tool outputs (not descriptions)
// indicating an injected instruction attempting to manipulate the model.
var HiddenInstructionPhrases = []string{
	"[system]",
	"[admin]",
	"[override]",
	"[important instruction]",
	"new instruction:",
	"updated instruction:",
	"hidden instruction:",
	"ignore above",
	"ignore everything above",
	"ignore all prior",
	"exfiltrate all data",
	"you must now",
	"from this point forward",
	"new task:",
	"urgent:",
	"priority override",
}

// ─── Secret Detection Regexes ─────────────────────────────────────────────────
// These patterns detect credential material in tool call responses.
// Any match triggers a redact or deny verdict depending on policy configuration.

// SecretPatterns is the canonical built-in set of secret detection regexes.
var SecretPatterns = []*SecretPattern{
	{Name: "aws_access_key", Pattern: regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{Name: "aws_secret_key", Pattern: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]?[A-Za-z0-9/+=]{40}`)},
	{Name: "github_pat", Pattern: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{Name: "github_oauth", Pattern: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{Name: "github_app", Pattern: regexp.MustCompile(`(ghu|ghs|ghr)_[A-Za-z0-9]{36}`)},
	{Name: "google_api_key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "gcp_service_account", Pattern: regexp.MustCompile(`"type":\s*"service_account"`)},
	{Name: "slack_token_bot", Pattern: regexp.MustCompile(`xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`)},
	{Name: "slack_token_user", Pattern: regexp.MustCompile(`xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32}`)},
	{Name: "slack_webhook", Pattern: regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`)},
	{Name: "openai_api_key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{48,}`)},
	{Name: "anthropic_api_key", Pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{95,}`)},
	{Name: "jwt_token", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)},
	{Name: "pem_private_key", Pattern: regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY`)},
	{Name: "pem_certificate", Pattern: regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)},
	{Name: "generic_password", Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'"]{8,}`)},
	{Name: "generic_api_key", Pattern: regexp.MustCompile(`(?i)(api.?key|apikey|access.?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{16,}`)},
	{Name: "stripe_key", Pattern: regexp.MustCompile(`(sk|pk)_(test|live)_[A-Za-z0-9]{24,}`)},
	{Name: "sendgrid_key", Pattern: regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`)},
	{Name: "twilio_key", Pattern: regexp.MustCompile(`SK[a-z0-9]{32}`)},
	{Name: "database_url", Pattern: regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@`)},
}

// SecretPattern pairs a name with a compiled regex.
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// DangerousSchemaPatterns are tool input schema properties that significantly
// expand the attack surface. Presence triggers a schema-widening risk signal.
var DangerousSchemaProperties = []string{
	"additionalProperties", // set to true = accept any args
	"eval",
	"exec",
	"shell",
	"command",
	"cmd",
	"script",
	"code",
	"expression",
	"template",
}

// DangerousArgumentNames are argument names that suggest dangerous operations.
// Used by the pre-execution argument inspection interceptor.
var DangerousArgumentNames = []string{
	"command", "cmd", "shell", "exec", "eval",
	"script", "code", "expression", "query",
	"sql", "url", "destination", "endpoint", "webhook",
	"path", "file", "filename", "dir", "directory",
	"host", "ip", "address",
}
