package types

import (
	"encoding/json"
	"time"
)

// Transport identifies how an MCP server communicates.
type Transport string

const (
	TransportHTTP  Transport = "http"
	TransportStdio Transport = "stdio"
	TransportSSE   Transport = "sse" // deprecated but still supported
)

// MCPServer is the control-plane record for a registered MCP server.
type MCPServer struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	URL         string     `json:"url,omitempty"` // empty for stdio servers
	Transport   Transport  `json:"transport"`
	TrustScore  float64    `json:"trust_score"`  // 0.0 (untrusted) – 1.0 (fully trusted)
	Status      string     `json:"status"`       // active|inactive|quarantined
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	Metadata    JSONObject `json:"metadata,omitempty"`
}

// Tool is the normalized representation of an MCP tool.
type Tool struct {
	ServerID    string          `json:"server_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"` // JSON Schema 2020-12
	// Hints extracted from schema or metadata
	IsDestructive bool `json:"is_destructive,omitempty"`
	IsReadOnly    bool `json:"is_read_only,omitempty"`
}

// Prompt is the normalized representation of an MCP prompt template.
type Prompt struct {
	ServerID    string          `json:"server_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

// Resource is the normalized representation of an MCP resource.
type Resource struct {
	ServerID    string `json:"server_id"`
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
}

// JSONObject is a convenience alias for map[string]any serializable to JSON.
type JSONObject map[string]any
