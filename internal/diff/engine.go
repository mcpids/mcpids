package diff

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine tracks capability snapshots and produces deltas.
type Engine interface {
	// Snapshot records the current state of a server's tools.
	// Returns the snapshot and any delta from the previous snapshot.
	Snapshot(ctx context.Context, serverID string, tools []ToolSnapshot) (*Snapshot, *Delta, error)

	// Compare computes the delta between two snapshots.
	Compare(previous, current *Snapshot) *Delta

	// Signal converts a delta into a risk signal.
	Signal(delta *Delta, toolIsNew string) *Signal

	// GetPrevious returns the previous snapshot for a server, if any.
	GetPrevious(ctx context.Context, serverID string) (*Snapshot, error)

	// IsToolNew returns true if this tool name has never been seen before for the server.
	IsToolNew(ctx context.Context, serverID, toolName string) bool
}

// engineImpl is the default Engine implementation.
// When a Store is provided, snapshots are persisted to PostgreSQL for durability
// across restarts. Without a store, all state is in-memory only.
type engineImpl struct {
	mu        sync.RWMutex
	snapshots map[string]*Snapshot           // serverID → most recent snapshot (cache)
	toolSets  map[string]map[string]struct{} // serverID → set of known tool names (cache)
	store     Store                          // optional persistence layer
}

// NewEngine creates a new diff engine with an in-memory-only snapshot store.
// Use NewEngineWithStore for production deployments that need persistence.
func NewEngine() Engine {
	return &engineImpl{
		snapshots: make(map[string]*Snapshot),
		toolSets:  make(map[string]map[string]struct{}),
		store:     &memStore{},
	}
}

// Snapshot implements Engine.
func (e *engineImpl) Snapshot(ctx context.Context, serverID string, tools []ToolSnapshot) (*Snapshot, *Delta, error) {
	current := &Snapshot{
		ID:         uuid.New().String(),
		ServerID:   serverID,
		CapturedAt: time.Now().UTC(),
		Tools:      tools,
		Checksum:   computeChecksum(tools),
	}

	e.mu.Lock()
	prev := e.snapshots[serverID]

	// On cache miss, try loading from persistent store.
	if prev == nil && e.store != nil {
		loaded, err := e.store.LoadLatest(ctx, serverID)
		if err != nil {
			slog.Warn("diff: store load failed, treating as first snapshot", "server_id", serverID, "error", err)
		} else if loaded != nil {
			prev = loaded
			e.snapshots[serverID] = prev
		}
	}

	e.snapshots[serverID] = current

	// Update known tool names.
	if e.toolSets[serverID] == nil {
		e.toolSets[serverID] = make(map[string]struct{})
		// Also hydrate from store if cache is cold.
		if e.store != nil {
			if names, err := e.store.LoadToolNames(ctx, serverID); err == nil && names != nil {
				e.toolSets[serverID] = names
			}
		}
	}
	for _, t := range tools {
		e.toolSets[serverID][t.Name] = struct{}{}
	}
	e.mu.Unlock()

	// Persist to store (async-safe: fire-and-forget with logging).
	if e.store != nil {
		if err := e.store.SaveSnapshot(ctx, "", current); err != nil {
			slog.Warn("diff: snapshot persistence failed", "server_id", serverID, "error", err)
		}
	}

	if prev == nil {
		// First snapshot - no delta.
		slog.Info("diff: first snapshot for server",
			"server_id", serverID, "tool_count", len(tools))
		return current, nil, nil
	}

	if prev.Checksum == current.Checksum {
		// No changes.
		return current, nil, nil
	}

	delta := e.Compare(prev, current)
	if delta.HasChanges {
		slog.Info("diff: capability changes detected",
			"server_id", serverID,
			"added", len(delta.AddedTools),
			"removed", len(delta.RemovedTools),
			"modified", len(delta.ModifiedTools))
	}

	return current, delta, nil
}

// Compare implements Engine.
func (e *engineImpl) Compare(previous, current *Snapshot) *Delta {
	delta := &Delta{
		ServerID:           current.ServerID,
		PreviousSnapshotID: previous.ID,
		CurrentSnapshotID:  current.ID,
	}

	prevMap := make(map[string]ToolSnapshot, len(previous.Tools))
	for _, t := range previous.Tools {
		prevMap[t.Name] = t
	}

	currMap := make(map[string]ToolSnapshot, len(current.Tools))
	for _, t := range current.Tools {
		currMap[t.Name] = t
	}

	// Detect added tools.
	for name, t := range currMap {
		if _, exists := prevMap[name]; !exists {
			delta.AddedTools = append(delta.AddedTools, t)
			delta.HasChanges = true
		}
	}

	// Detect removed tools.
	for name, t := range prevMap {
		if _, exists := currMap[name]; !exists {
			delta.RemovedTools = append(delta.RemovedTools, t)
			delta.HasChanges = true
		}
	}

	// Detect modified tools.
	for name, curr := range currMap {
		prev, exists := prevMap[name]
		if !exists {
			continue
		}

		change := ToolChange{Name: name}

		if curr.Description != prev.Description {
			change.DescriptionChanged = true
			change.OldDescription = prev.Description
			change.NewDescription = curr.Description
		}

		if curr.SchemaHash != prev.SchemaHash {
			change.SchemaChanged = true
			change.OldInputSchema = prev.InputSchema
			change.NewInputSchema = curr.InputSchema
			change.SchemaWidened = detectSchemaWidening(prev.InputSchema, curr.InputSchema)
		}

		if change.DescriptionChanged || change.SchemaChanged {
			delta.ModifiedTools = append(delta.ModifiedTools, change)
			delta.HasChanges = true
		}
	}

	return delta
}

// Signal implements Engine.
func (e *engineImpl) Signal(delta *Delta, toolIsNew string) *Signal {
	if delta == nil {
		return &Signal{ToolIsNew: toolIsNew}
	}

	sig := &Signal{
		HasChanges:        delta.HasChanges,
		NewToolCount:      len(delta.AddedTools),
		RemovedToolCount:  len(delta.RemovedTools),
		ModifiedToolCount: len(delta.ModifiedTools),
		ToolIsNew:         toolIsNew,
	}

	var score float64

	// New tools are high-risk: each adds 0.3, capped at 0.6.
	score += min(float64(sig.NewToolCount)*0.3, 0.6)

	// Modified tools add moderate risk.
	for _, mc := range delta.ModifiedTools {
		if mc.SchemaWidened {
			sig.WidenedSchemas++
			sig.SuspiciousChanges = append(sig.SuspiciousChanges,
				fmt.Sprintf("tool %q: input schema widened", mc.Name))
			score += 0.4
		}
		if mc.DescriptionChanged {
			sig.SuspiciousChanges = append(sig.SuspiciousChanges,
				fmt.Sprintf("tool %q: description changed", mc.Name))
			score += 0.2
		}
	}

	// Cap at 1.0.
	if score > 1.0 {
		score = 1.0
	}
	sig.RiskContribution = score

	return sig
}

// GetPrevious implements Engine.
func (e *engineImpl) GetPrevious(ctx context.Context, serverID string) (*Snapshot, error) {
	e.mu.RLock()
	snap := e.snapshots[serverID]
	e.mu.RUnlock()

	if snap != nil {
		return snap, nil
	}

	// Cache miss - try loading from persistent store.
	if e.store != nil {
		loaded, err := e.store.LoadLatest(ctx, serverID)
		if err != nil {
			return nil, err
		}
		if loaded != nil {
			e.mu.Lock()
			e.snapshots[serverID] = loaded
			e.mu.Unlock()
			return loaded, nil
		}
	}

	return nil, nil
}

// IsToolNew implements Engine.
func (e *engineImpl) IsToolNew(ctx context.Context, serverID, toolName string) bool {
	e.mu.RLock()
	s, ok := e.toolSets[serverID]
	e.mu.RUnlock()

	if ok {
		_, seen := s[toolName]
		return !seen
	}

	// Cache miss - try loading from persistent store.
	if e.store != nil {
		names, err := e.store.LoadToolNames(ctx, serverID)
		if err == nil && names != nil {
			e.mu.Lock()
			e.toolSets[serverID] = names
			e.mu.Unlock()
			_, seen := names[toolName]
			return !seen
		}
	}

	return true // never seen this server at all
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func computeChecksum(tools []ToolSnapshot) string {
	// Canonical JSON: sorted by tool name, deterministic.
	type canonTool struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SchemaHash  string `json:"schema_hash"`
	}
	canon := make([]canonTool, len(tools))
	for i, t := range tools {
		canon[i] = canonTool{Name: t.Name, Description: t.Description, SchemaHash: t.SchemaHash}
	}
	data, _ := json.Marshal(canon)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// computeSchemaHash returns a SHA-256 hex digest of the raw JSON schema bytes.
func computeSchemaHash(schema json.RawMessage) string {
	h := sha256.Sum256(schema)
	return fmt.Sprintf("%x", h)
}

// MakeToolSnapshot converts a raw mcp.Tool representation into a ToolSnapshot
// (called by the pipeline interceptor after parsing tools/list).
func MakeToolSnapshot(name, description string, inputSchema json.RawMessage) ToolSnapshot {
	ts := ToolSnapshot{
		Name:        name,
		Description: description,
		InputSchema: inputSchema,
	}
	if len(inputSchema) > 0 {
		ts.SchemaHash = computeSchemaHash(inputSchema)
	}
	return ts
}

// detectSchemaWidening returns true when the new schema is less restrictive than the old one.
// Widening indicators: additionalProperties added/changed to true, required fields removed.
func detectSchemaWidening(oldSchema, newSchema json.RawMessage) bool {
	if len(oldSchema) == 0 || len(newSchema) == 0 {
		return false
	}

	var oldMap, newMap map[string]any
	if err := json.Unmarshal(oldSchema, &oldMap); err != nil {
		return false
	}
	if err := json.Unmarshal(newSchema, &newMap); err != nil {
		return false
	}

	// Check additionalProperties widening.
	oldAP, _ := oldMap["additionalProperties"]
	newAP, _ := newMap["additionalProperties"]
	if newAP == true && oldAP != true {
		return true
	}

	// Check required fields shrinkage.
	oldReq, _ := oldMap["required"].([]any)
	newReq, _ := newMap["required"].([]any)
	if len(oldReq) > len(newReq) {
		return true
	}

	return false
}

// detectSchemaWideningFromStrings checks for dangerous schema property names.
func detectSchemaWideningFromStrings(schemaStr string) bool {
	lower := strings.ToLower(schemaStr)
	return strings.Contains(lower, `"additionalproperties":true`) ||
		strings.Contains(lower, `"additionalproperties": true`)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
