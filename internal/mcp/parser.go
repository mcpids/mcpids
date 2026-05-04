package mcp

import (
	"encoding/json"
	"fmt"
)

// DefaultMaxMessageSize is the maximum JSON-RPC message size accepted by the parser.
// Messages larger than this are rejected to prevent memory exhaustion.
const DefaultMaxMessageSize = 4 * 1024 * 1024 // 4 MiB

// Parser parses JSON-RPC 2.0 messages. It is safe for concurrent use.
type Parser struct {
	maxSize int
}

// NewParser creates a Parser with the given maximum message size in bytes.
// Use DefaultMaxMessageSize if you have no specific requirement.
func NewParser(maxSize int) *Parser {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &Parser{maxSize: maxSize}
}

// ParseMessage parses raw bytes into a JSONRPCMessage.
// Returns an error if the payload exceeds maxSize, is not valid JSON, or
// does not conform to JSON-RPC 2.0.
func (p *Parser) ParseMessage(data []byte) (*JSONRPCMessage, error) {
	if len(data) > p.maxSize {
		return nil, fmt.Errorf("mcp: message size %d exceeds limit %d", len(data), p.maxSize)
	}

	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("mcp: invalid JSON-RPC envelope: %w", err)
	}

	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("mcp: expected jsonrpc=2.0, got %q", msg.JSONRPC)
	}

	return &msg, nil
}

// Kind determines the kind of a JSON-RPC message without further parsing.
func (p *Parser) Kind(msg *JSONRPCMessage) MessageKind {
	switch {
	case msg.Error != nil:
		return KindError
	case msg.ID == nil && msg.Method != "":
		return KindNotification
	case msg.ID != nil && msg.Method != "":
		return KindRequest
	default:
		return KindResponse
	}
}

// ParseToolsListResult extracts ToolsListResult from a response result field.
func ParseToolsListResult(result json.RawMessage) (*ToolsListResult, error) {
	var r ToolsListResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse tools/list result: %w", err)
	}
	return &r, nil
}

// ParseToolCallParams extracts ToolCallParams from a request params field.
func ParseToolCallParams(params json.RawMessage) (*ToolCallParams, error) {
	var p ToolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("mcp: parse tools/call params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("mcp: tools/call params missing required field 'name'")
	}
	return &p, nil
}

// ParseToolCallResult extracts ToolCallResult from a response result field.
func ParseToolCallResult(result json.RawMessage) (*ToolCallResult, error) {
	var r ToolCallResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse tools/call result: %w", err)
	}
	return &r, nil
}

// ParseInitializeParams extracts InitializeParams from a request params field.
func ParseInitializeParams(params json.RawMessage) (*InitializeParams, error) {
	var p InitializeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("mcp: parse initialize params: %w", err)
	}
	if p.ProtocolVersion == "" {
		return nil, fmt.Errorf("mcp: initialize params missing required field 'protocolVersion'")
	}
	return &p, nil
}

// ParseInitializeResult extracts InitializeResult from a response result field.
func ParseInitializeResult(result json.RawMessage) (*InitializeResult, error) {
	var r InitializeResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse initialize result: %w", err)
	}
	return &r, nil
}

// ParsePromptsListResult extracts PromptsListResult from a response result field.
func ParsePromptsListResult(result json.RawMessage) (*PromptsListResult, error) {
	var r PromptsListResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse prompts/list result: %w", err)
	}
	return &r, nil
}

// ParseResourcesListResult extracts ResourcesListResult from a response result field.
func ParseResourcesListResult(result json.RawMessage) (*ResourcesListResult, error) {
	var r ResourcesListResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse resources/list result: %w", err)
	}
	return &r, nil
}

// ParseResourcesReadResult extracts ResourcesReadResult from a response result field.
func ParseResourcesReadResult(result json.RawMessage) (*ResourcesReadResult, error) {
	var r ResourcesReadResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("mcp: parse resources/read result: %w", err)
	}
	return &r, nil
}

// ParseResourcesReadParams extracts ResourcesReadParams from a request params field.
func ParseResourcesReadParams(params json.RawMessage) (*ResourcesReadParams, error) {
	var p ResourcesReadParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("mcp: parse resources/read params: %w", err)
	}
	if p.URI == "" {
		return nil, fmt.Errorf("mcp: resources/read params missing required field 'uri'")
	}
	return &p, nil
}

// ErrorResponse builds a JSON-RPC error response for the given request ID.
func ErrorResponse(id json.RawMessage, code int, message string) *JSONRPCMessage {
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
}

// DenyResponse builds the standard MCPIDS deny error response.
func DenyResponse(id json.RawMessage, reason string) *JSONRPCMessage {
	msg := "request denied by policy"
	if reason != "" {
		msg = reason
	}
	return ErrorResponse(id, CodeDeniedByPolicy, msg)
}

// QuarantineResponse builds the standard MCPIDS quarantine error response.
func QuarantineResponse(id json.RawMessage) *JSONRPCMessage {
	return ErrorResponse(id, CodeSessionQuarantined, "session has been quarantined")
}
