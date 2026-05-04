// Package schema validates MCP tool call arguments against advertised JSON Schemas.
package schema

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/mcpids/mcpids/internal/diff"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidationResult reports whether a tool call argument payload matches schema.
type ValidationResult struct {
	Valid  bool
	Reason string
}

// Validator stores compiled schemas and validates arguments on the hot path.
type Validator interface {
	// RegisterToolSchema compiles and caches the schema for serverID/toolName.
	RegisterToolSchema(ctx context.Context, serverID, toolName string, schema json.RawMessage) error

	// ValidateToolCall checks arguments against the cached schema for serverID/toolName.
	// Calls for unknown tools/schemas are denied after a snapshot hydration attempt.
	// Calls for tools that are known to have no input schema are allowed.
	ValidateToolCall(ctx context.Context, serverID, toolName string, arguments json.RawMessage) ValidationResult

	// WarmUp proactively loads schemas for the given server IDs from the backing
	// store so that the first tools/call is not denied due to a missing snapshot.
	// It is a no-op when no store is configured. Errors are non-fatal.
	WarmUp(ctx context.Context, serverIDs []string) error
}

type schemaKey struct {
	serverID string
	toolName string
}

type validatorImpl struct {
	mu        sync.RWMutex
	schemas   map[schemaKey]*jsonschema.Schema
	noSchemas map[schemaKey]struct{}
	store     diff.Store
}

// NewValidator creates a schema validator with an in-memory compiled schema cache.
func NewValidator() Validator {
	return NewValidatorWithStore(nil)
}

// NewValidatorWithStore creates a validator that can hydrate unknown schemas
// from the latest persisted tools/list snapshot for a server.
func NewValidatorWithStore(store diff.Store) Validator {
	return &validatorImpl{
		schemas:   make(map[schemaKey]*jsonschema.Schema),
		noSchemas: make(map[schemaKey]struct{}),
		store:     store,
	}
}

// RegisterToolSchema implements Validator.
func (v *validatorImpl) RegisterToolSchema(_ context.Context, serverID, toolName string, schemaBytes json.RawMessage) error {
	key := schemaKey{serverID: serverID, toolName: toolName}
	if len(bytes.TrimSpace(schemaBytes)) == 0 || bytes.Equal(bytes.TrimSpace(schemaBytes), []byte("null")) {
		v.mu.Lock()
		delete(v.schemas, key)
		v.noSchemas[key] = struct{}{}
		v.mu.Unlock()
		return nil
	}

	compiler := jsonschema.NewCompiler()
	schemaURI := fmt.Sprintf("mem://mcpids/%s/%s.json", serverID, toolName)
	var schemaDoc any
	if err := json.Unmarshal(schemaBytes, &schemaDoc); err != nil {
		return fmt.Errorf("schema: parse %s/%s: %w", serverID, toolName, err)
	}
	if err := compiler.AddResource(schemaURI, schemaDoc); err != nil {
		return fmt.Errorf("schema: add resource %s/%s: %w", serverID, toolName, err)
	}
	compiled, err := compiler.Compile(schemaURI)
	if err != nil {
		return fmt.Errorf("schema: compile %s/%s: %w", serverID, toolName, err)
	}

	v.mu.Lock()
	v.schemas[key] = compiled
	delete(v.noSchemas, key)
	v.mu.Unlock()
	return nil
}

// ValidateToolCall implements Validator.
func (v *validatorImpl) ValidateToolCall(ctx context.Context, serverID, toolName string, arguments json.RawMessage) ValidationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	compiled, known := v.lookupCompiledSchema(serverID, toolName)
	if !known && v.store != nil && strings.TrimSpace(serverID) != "" && strings.TrimSpace(toolName) != "" {
		if err := v.hydrateServerSchemas(ctx, serverID); err != nil {
			return ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("schema cache preload failed: %v", err),
			}
		}
		compiled, known = v.lookupCompiledSchema(serverID, toolName)
	}
	if !known {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("schema not found for %s/%s", serverID, toolName),
		}
	}
	if compiled == nil {
		return ValidationResult{Valid: true}
	}

	var payload any = map[string]any{}
	if len(bytes.TrimSpace(arguments)) > 0 && !bytes.Equal(bytes.TrimSpace(arguments), []byte("null")) {
		if err := json.Unmarshal(arguments, &payload); err != nil {
			return ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("invalid arguments JSON: %v", err),
			}
		}
	}

	if err := compiled.Validate(payload); err != nil {
		return ValidationResult{
			Valid:  false,
			Reason: strings.TrimSpace(err.Error()),
		}
	}

	return ValidationResult{Valid: true}
}

func (v *validatorImpl) lookupCompiledSchema(serverID, toolName string) (*jsonschema.Schema, bool) {
	v.mu.RLock()
	key := schemaKey{serverID: serverID, toolName: toolName}
	compiled, hasSchema := v.schemas[key]
	_, hasNoSchema := v.noSchemas[key]
	v.mu.RUnlock()
	return compiled, hasSchema || hasNoSchema
}

// WarmUp implements Validator.
func (v *validatorImpl) WarmUp(ctx context.Context, serverIDs []string) error {
	if v.store == nil {
		return nil
	}
	for _, id := range serverIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if err := v.hydrateServerSchemas(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (v *validatorImpl) hydrateServerSchemas(ctx context.Context, serverID string) error {
	snapshot, err := v.store.LoadLatest(ctx, serverID)
	if err != nil || snapshot == nil {
		return err
	}
	for _, tool := range snapshot.Tools {
		if strings.TrimSpace(tool.Name) == "" {
			continue
		}
		if err := v.RegisterToolSchema(ctx, serverID, tool.Name, tool.InputSchema); err != nil {
			return err
		}
	}
	return nil
}
