// Package mcp implements the Model Context Protocol (MCP) message types and parsing.
// Protocol version: 2025-11-25
// Spec: https://modelcontextprotocol.io/specification/2025-11-25
package mcp

import (
	"encoding/json"
)

// MCP JSON-RPC method names (protocol version 2025-11-25).
const (
	MethodInitialize         = "initialize"
	MethodInitialized        = "notifications/initialized"
	MethodPing               = "ping"
	MethodToolsList          = "tools/list"
	MethodToolsCall          = "tools/call"
	MethodPromptsList        = "prompts/list"
	MethodPromptsGet         = "prompts/get"
	MethodResourcesList      = "resources/list"
	MethodResourcesRead      = "resources/read"
	MethodResourcesSubscribe = "resources/subscribe"
	MethodResourcesTemplates = "resources/templates/list"
	MethodCancelled          = "notifications/cancelled"
	MethodProgress           = "notifications/progress"
	MethodToolsListChanged   = "notifications/tools/list_changed"
	MethodPromptsListChanged = "notifications/prompts/list_changed"
	MethodResourcesUpdated   = "notifications/resources/updated"

	// ProtocolVersion is the MCP protocol version this implementation targets.
	ProtocolVersion = "2025-11-25"
)

// Direction indicates whether a message flows from client→server or server→client.
type Direction string

const (
	DirectionInbound  Direction = "inbound"  // client → upstream server
	DirectionOutbound Direction = "outbound" // upstream server → client/agent
)

// MessageKind classifies a JSON-RPC 2.0 message.
type MessageKind int

const (
	KindRequest      MessageKind = iota // has id + method
	KindResponse                        // has id + result or error
	KindNotification                    // has method, no id
	KindError                           // has id + error
)

// JSONRPCMessage is the raw JSON-RPC 2.0 envelope.
// All MCP messages are encoded in this format.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`     // string | number | null; absent for notifications
	Method  string          `json:"method,omitempty"` // absent for responses
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is the standard JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	// MCP-specific
	CodeRequestCancelled  = -32800
	CodeContentTooLarge   = -32801
	CodeResourceNotFound  = -32002
	// MCPIDS custom
	CodeDeniedByPolicy    = -32001
	CodeSessionQuarantined = -32010
	CodeApprovalRequired  = -32011
)

// ─── initialize ────────────────────────────────────────────────────────────────

// InitializeParams is the payload for the initialize request (client → server).
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is the response to initialize (server → client).
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// Implementation identifies a client or server by name and version.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientCapabilities declares what the client supports.
type ClientCapabilities struct {
	Roots    *RootsCapability    `json:"roots,omitempty"`
	Sampling *SamplingCapability `json:"sampling,omitempty"`
	// Experimental is a freeform map for non-standard capabilities.
	Experimental map[string]any `json:"experimental,omitempty"`
}

// ServerCapabilities declares what the server supports.
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Logging   *LoggingCapability   `json:"logging,omitempty"`
	// Experimental is a freeform map for non-standard capabilities.
	Experimental map[string]any `json:"experimental,omitempty"`
}

type RootsCapability    struct{ ListChanged bool `json:"listChanged,omitempty"` }
type SamplingCapability struct{}
type LoggingCapability  struct{}
type ToolsCapability     struct{ ListChanged bool `json:"listChanged,omitempty"` }
type PromptsCapability   struct{ ListChanged bool `json:"listChanged,omitempty"` }
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// ─── tools/list ────────────────────────────────────────────────────────────────

// ToolsListParams is the optional cursor for pagination.
type ToolsListParams struct {
	Cursor *string `json:"cursor,omitempty"`
}

// ToolsListResult is the response payload for tools/list.
type ToolsListResult struct {
	Tools      []Tool  `json:"tools"`
	NextCursor *string `json:"nextCursor,omitempty"`
}

// Tool is a callable function exposed by an MCP server.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"` // JSON Schema 2020-12
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
}

// ─── tools/call ────────────────────────────────────────────────────────────────

// ToolCallParams is the request payload for tools/call.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolCallResult is the response payload for tools/call.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a single unit of content in a tool response.
type ContentBlock struct {
	Type     string `json:"type"`           // text | image | resource
	Text     string `json:"text,omitempty"` // for type=text
	MimeType string `json:"mimeType,omitempty"`
	Data     string `json:"data,omitempty"` // base64 for type=image
}

// ─── prompts/list + prompts/get ────────────────────────────────────────────────

type PromptsListParams struct {
	Cursor *string `json:"cursor,omitempty"`
}

type PromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor *string  `json:"nextCursor,omitempty"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptsGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type PromptsGetResult struct {
	Description string           `json:"description,omitempty"`
	Messages    []PromptMessage  `json:"messages"`
}

type PromptMessage struct {
	Role    string       `json:"role"` // user | assistant
	Content ContentBlock `json:"content"`
}

// ─── resources/list + resources/read ────────────────────────────────────────────

type ResourcesListParams struct {
	Cursor *string `json:"cursor,omitempty"`
}

type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor *string    `json:"nextCursor,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourcesReadParams struct {
	URI string `json:"uri"`
}

type ResourcesReadResult struct {
	Contents []ResourceContent `json:"contents"`
}

type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"` // for text resources
	Blob     string `json:"blob,omitempty"` // base64 for binary resources
}
