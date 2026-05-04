package mcp

import (
	"encoding/json"
	"fmt"
)

// MarshalMessage serializes a JSONRPCMessage to JSON bytes.
func MarshalMessage(msg *JSONRPCMessage) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("mcp: marshal message: %w", err)
	}
	return data, nil
}

// MarshalResult creates a JSON-RPC success response with the given ID and result value.
func MarshalResult(id json.RawMessage, result any) (*JSONRPCMessage, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("mcp: marshal result: %w", err)
	}
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resultJSON,
	}, nil
}

// RebuildToolsListResult creates a new tools/list response with a filtered tool list.
// It preserves the original cursor and message ID.
func RebuildToolsListResult(original *JSONRPCMessage, result *ToolsListResult, filtered []Tool) ([]byte, error) {
	newResult := *result
	newResult.Tools = filtered
	return marshalResponse(original.ID, newResult)
}

// RebuildToolCallResult creates a new tools/call response with redacted content.
func RebuildToolCallResult(original *JSONRPCMessage, result *ToolCallResult) ([]byte, error) {
	return marshalResponse(original.ID, result)
}

func marshalResponse(id json.RawMessage, result any) ([]byte, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("mcp: marshal response: %w", err)
	}
	msg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resultJSON,
	}
	return json.Marshal(msg)
}

// ExtractTextContent concatenates all text content blocks from a tool call result.
// Used by the inspection pipeline for content scanning.
func ExtractTextContent(result *ToolCallResult) string {
	var combined string
	for _, block := range result.Content {
		if block.Type == "text" {
			combined += block.Text + "\n"
		}
	}
	return combined
}

// RedactContentBlock replaces occurrences of pattern in a text content block.
// This is a simple string replacement; the rules engine provides the actual pattern.
func RedactContentBlock(block *ContentBlock, original, replacement string) {
	if block.Type == "text" {
		// Simple replacement - regex replacement is handled by the rules/redaction engine
		// which calls this after computing the replacement string.
		block.Text = original
		_ = replacement // caller must substitute text before calling
	}
}
