package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MatchResult holds the outcome of a single condition evaluation.
type MatchResult struct {
	Matched  bool
	Evidence string // human-readable description of what matched
}

// EvaluateCondition evaluates a single Condition against the extracted field value.
// fieldValue is the string value of the field referenced by cond.Field.
// engine provides access to phrase sets and schema validator.
func EvaluateCondition(cond Condition, fieldValue string, e *engineImpl) MatchResult {
	result := evaluateOp(cond, fieldValue, e)
	if cond.Negate {
		result.Matched = !result.Matched
		if result.Matched {
			result.Evidence = fmt.Sprintf("NOT(%s)", result.Evidence)
		}
	}
	return result
}

func evaluateOp(cond Condition, value string, e *engineImpl) MatchResult {
	switch cond.Op {
	case OpEquals:
		target := fmt.Sprintf("%v", cond.Value)
		matched := value == target
		evidence := ""
		if matched {
			evidence = fmt.Sprintf("field equals %q", target)
		}
		return MatchResult{Matched: matched, Evidence: evidence}

	case OpContains:
		target := fmt.Sprintf("%v", cond.Value)
		matched := strings.Contains(strings.ToLower(value), strings.ToLower(target))
		evidence := ""
		if matched {
			evidence = fmt.Sprintf("field contains %q", target)
		}
		return MatchResult{Matched: matched, Evidence: evidence}

	case OpRegex:
		pattern := fmt.Sprintf("%v", cond.Value)
		re, err := getOrCompileRegex(e, pattern)
		if err != nil {
			return MatchResult{Matched: false, Evidence: fmt.Sprintf("invalid regex %q: %v", pattern, err)}
		}
		loc := re.FindStringIndex(value)
		if loc == nil {
			return MatchResult{Matched: false}
		}
		return MatchResult{
			Matched:  true,
			Evidence: fmt.Sprintf("field matches regex %q: found %q", pattern, value[loc[0]:loc[1]]),
		}

	case OpRegexAny:
		patterns, ok := toStringSlice(cond.Value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "regex_any: value must be []string"}
		}
		for _, p := range patterns {
			re, err := getOrCompileRegex(e, p)
			if err != nil {
				continue
			}
			if loc := re.FindStringIndex(value); loc != nil {
				return MatchResult{
					Matched:  true,
					Evidence: fmt.Sprintf("field matches regex %q: found %q", p, value[loc[0]:loc[1]]),
				}
			}
		}
		return MatchResult{Matched: false}

	case OpIn:
		targets, ok := toStringSlice(cond.Value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "in: value must be []string"}
		}
		for _, t := range targets {
			if strings.EqualFold(value, t) {
				return MatchResult{Matched: true, Evidence: fmt.Sprintf("field %q is in list", value)}
			}
		}
		return MatchResult{Matched: false}

	case OpExists:
		matched := value != ""
		evidence := ""
		if matched {
			evidence = "field exists and is non-empty"
		}
		return MatchResult{Matched: matched, Evidence: evidence}

	case OpPhraseMatch:
		setName := fmt.Sprintf("%v", cond.Value)
		matched, phrase := matchPhraseSet(e, setName, value)
		if matched {
			return MatchResult{
				Matched:  true,
				Evidence: fmt.Sprintf("field contains suspicious phrase %q (set: %s)", phrase, setName),
			}
		}
		return MatchResult{Matched: false}

	case OpSecretPattern:
		for _, sp := range SecretPatterns {
			if loc := sp.Pattern.FindStringIndex(value); loc != nil {
				snippet := value[loc[0]:loc[1]]
				if len(snippet) > 12 {
					snippet = snippet[:6] + "..." + snippet[len(snippet)-3:]
				}
				return MatchResult{
					Matched:  true,
					Evidence: fmt.Sprintf("secret pattern %q matched: %q", sp.Name, snippet),
				}
			}
		}
		return MatchResult{Matched: false}

	case OpGt:
		current, ok := toFloat64(value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "gt: field value is not numeric"}
		}
		target, ok := toFloat64(cond.Value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "gt: comparison value is not numeric"}
		}
		if current > target {
			return MatchResult{
				Matched:  true,
				Evidence: fmt.Sprintf("field %v is greater than %v", current, target),
			}
		}
		return MatchResult{Matched: false}

	case OpLt:
		current, ok := toFloat64(value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "lt: field value is not numeric"}
		}
		target, ok := toFloat64(cond.Value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "lt: comparison value is not numeric"}
		}
		if current < target {
			return MatchResult{
				Matched:  true,
				Evidence: fmt.Sprintf("field %v is less than %v", current, target),
			}
		}
		return MatchResult{Matched: false}

	case OpToolNameMatch:
		targets, ok := toStringSlice(cond.Value)
		if !ok {
			return MatchResult{Matched: false, Evidence: "tool_name_match: value must be string or []string"}
		}
		for _, t := range targets {
			if strings.EqualFold(value, t) {
				return MatchResult{Matched: true, Evidence: fmt.Sprintf("tool name %q matched list entry %q", value, t)}
			}
		}
		return MatchResult{Matched: false}

	case OpSchemaViolation:
		if strings.TrimSpace(value) == "" {
			return MatchResult{Matched: false}
		}
		return MatchResult{
			Matched:  true,
			Evidence: fmt.Sprintf("schema violation: %s", value),
		}

	default:
		return MatchResult{Matched: false, Evidence: fmt.Sprintf("unknown op: %q", cond.Op)}
	}
}

// matchPhraseSet looks up the named phrase set and runs Aho-Corasick search.
func matchPhraseSet(e *engineImpl, setName, text string) (bool, string) {
	e.mu.RLock()
	phrases, ok := e.phraseSets[setName]
	e.mu.RUnlock()
	if !ok {
		return false, ""
	}
	lower := strings.ToLower(text)
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			return true, phrase
		}
	}
	return false, ""
}

// getOrCompileRegex returns a compiled regex from the engine cache or compiles it fresh.
func getOrCompileRegex(e *engineImpl, pattern string) (*regexp.Regexp, error) {
	if e != nil {
		e.mu.RLock()
		if re, ok := e.compiledRegexes[pattern]; ok {
			e.mu.RUnlock()
			return re, nil
		}
		e.mu.RUnlock()
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	if e != nil {
		e.mu.Lock()
		e.compiledRegexes[pattern] = re
		e.mu.Unlock()
	}
	return re, nil
}

// toStringSlice converts an interface{} value to []string.
// Handles []string, []interface{} (from YAML unmarshalling), and string (singleton).
func toStringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		result := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, s)
		}
		return result, true
	case string:
		return []string{t}, true
	default:
		return nil, false
	}
}

func toFloat64(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return n, err == nil
	default:
		return 0, false
	}
}
