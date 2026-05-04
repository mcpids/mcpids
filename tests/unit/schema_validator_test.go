package unit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mcpids/mcpids/internal/diff"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
)

type fakeSchemaStore struct {
	snapshot *diff.Snapshot
	err      error
}

func (s *fakeSchemaStore) SaveSnapshot(context.Context, string, *diff.Snapshot) error {
	return nil
}

func (s *fakeSchemaStore) LoadLatest(context.Context, string) (*diff.Snapshot, error) {
	return s.snapshot, s.err
}

func (s *fakeSchemaStore) LoadToolNames(context.Context, string) (map[string]struct{}, error) {
	return nil, nil
}

func TestSchemaValidatorHydratesFromLatestSnapshot(t *testing.T) {
	validator := schemapkg.NewValidatorWithStore(&fakeSchemaStore{
		snapshot: &diff.Snapshot{
			ID:       "snapshot-1",
			ServerID: "server-1",
			Tools: []diff.ToolSnapshot{{
				Name: "safe_echo",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"text": {"type": "string"}
					},
					"required": ["text"],
					"additionalProperties": false
				}`),
			}},
		},
	})

	result := validator.ValidateToolCall(
		context.Background(),
		"server-1",
		"safe_echo",
		json.RawMessage(`{"text":42}`),
	)
	if result.Valid {
		t.Fatalf("expected hydrated schema validation to fail")
	}
	if result.Reason == "" {
		t.Fatalf("expected validation failure reason")
	}
}

func TestSchemaValidatorDeniesUnknownSchema(t *testing.T) {
	validator := schemapkg.NewValidator()

	result := validator.ValidateToolCall(
		context.Background(),
		"server-unknown",
		"tool-unknown",
		json.RawMessage(`{"x":1}`),
	)
	if result.Valid {
		t.Fatalf("expected unknown schema to be denied")
	}
	if result.Reason == "" {
		t.Fatalf("expected unknown schema reason")
	}
}

func TestSchemaValidatorAllowsKnownToolWithoutSchema(t *testing.T) {
	validator := schemapkg.NewValidator()
	if err := validator.RegisterToolSchema(
		context.Background(),
		"server-1",
		"no_schema_tool",
		json.RawMessage(`null`),
	); err != nil {
		t.Fatalf("RegisterToolSchema: %v", err)
	}

	result := validator.ValidateToolCall(
		context.Background(),
		"server-1",
		"no_schema_tool",
		json.RawMessage(`{"x":1}`),
	)
	if !result.Valid {
		t.Fatalf("expected known no-schema tool to be allowed, got %q", result.Reason)
	}
}
