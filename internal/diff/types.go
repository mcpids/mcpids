// Package diff implements the MCP server capability snapshot and diff engine.
// It tracks changes to tools, prompts, and resources between observed states
// and produces risk signals for the policy engine.
package diff

import (
	"encoding/json"
	"time"
)

// Snapshot is an immutable point-in-time capture of a server's full capability set.
// Two snapshots can be compared to produce a Delta.
type Snapshot struct {
	ID         string         `json:"id"`
	ServerID   string         `json:"server_id"`
	CapturedAt time.Time      `json:"captured_at"`
	Checksum   string         `json:"checksum"` // SHA-256 of CanonicalJSON()
	Tools      []ToolSnapshot `json:"tools"`
}

// ToolSnapshot is the recorded state of a single tool at snapshot time.
type ToolSnapshot struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	SchemaHash  string          `json:"schema_hash"` // SHA-256 of input_schema
}

// Delta describes differences between two consecutive snapshots of the same server.
type Delta struct {
	ServerID           string           `json:"server_id"`
	PreviousSnapshotID string           `json:"previous_snapshot_id"`
	CurrentSnapshotID  string           `json:"current_snapshot_id"`
	AddedTools         []ToolSnapshot   `json:"added_tools,omitempty"`
	RemovedTools       []ToolSnapshot   `json:"removed_tools,omitempty"`
	ModifiedTools      []ToolChange     `json:"modified_tools,omitempty"`
	HasChanges         bool             `json:"has_changes"`
}

// ToolChange describes how a specific tool changed between snapshots.
type ToolChange struct {
	Name              string          `json:"name"`
	OldDescription    string          `json:"old_description"`
	NewDescription    string          `json:"new_description"`
	DescriptionChanged bool           `json:"description_changed"`
	OldInputSchema    json.RawMessage `json:"old_input_schema,omitempty"`
	NewInputSchema    json.RawMessage `json:"new_input_schema,omitempty"`
	SchemaChanged     bool            `json:"schema_changed"`
	// SchemaWidened is true when the new schema is less restrictive:
	// additionalProperties widened, required fields removed, or type widened.
	SchemaWidened bool `json:"schema_widened"`
}

// Signal is the risk contribution produced from a Delta.
// It is consumed by the risk engine as one of its signal inputs.
type Signal struct {
	HasChanges        bool     `json:"has_changes"`
	NewToolCount      int      `json:"new_tool_count"`
	RemovedToolCount  int      `json:"removed_tool_count"`
	ModifiedToolCount int      `json:"modified_tool_count"`
	WidenedSchemas    int      `json:"widened_schemas"`
	SuspiciousChanges []string `json:"suspicious_changes,omitempty"`
	// RiskContribution is a 0.0–1.0 contribution to the overall risk score.
	// 0.0 = no changes. Approaches 1.0 for many destructive changes.
	RiskContribution float64 `json:"risk_contribution"`
	// IsFirstSeen is true when this is the very first snapshot for the server.
	IsFirstSeen bool `json:"is_first_seen"`
	// ToolIsNew is set to the tool name when a tools/call is for a first-seen tool.
	ToolIsNew string `json:"tool_is_new,omitempty"`
}
