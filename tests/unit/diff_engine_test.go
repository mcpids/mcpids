package unit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mcpids/mcpids/internal/diff"
)

func tools(nameDesc ...string) []diff.ToolSnapshot {
	var ts []diff.ToolSnapshot
	for i := 0; i+1 < len(nameDesc); i += 2 {
		ts = append(ts, diff.MakeToolSnapshot(nameDesc[i], nameDesc[i+1], nil))
	}
	return ts
}

func TestDiffEngine_FirstSnapshot_NoDelta(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	_, delta, err := eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta != nil {
		t.Error("expected nil delta on first snapshot")
	}
}

func TestDiffEngine_NoChanges_NoDelta(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	ts := tools("read_file", "Read a file")
	_, _, _ = eng.Snapshot(ctx, "srv-1", ts)
	_, delta, err := eng.Snapshot(ctx, "srv-1", ts)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta != nil {
		t.Error("expected nil delta when tools unchanged")
	}
}

func TestDiffEngine_AddedTool(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	_, _, _ = eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))
	_, delta, err := eng.Snapshot(ctx, "srv-1", tools(
		"read_file", "Read a file",
		"rm_all", "Remove all files",
	))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta == nil {
		t.Fatal("expected non-nil delta when tool added")
	}
	if len(delta.AddedTools) != 1 {
		t.Errorf("AddedTools = %d, want 1", len(delta.AddedTools))
	}
	if delta.AddedTools[0].Name != "rm_all" {
		t.Errorf("AddedTools[0].Name = %q, want %q", delta.AddedTools[0].Name, "rm_all")
	}
}

func TestDiffEngine_RemovedTool(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	_, _, _ = eng.Snapshot(ctx, "srv-1", tools(
		"read_file", "Read a file",
		"write_file", "Write a file",
	))
	_, delta, err := eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta == nil || len(delta.RemovedTools) != 1 {
		t.Fatalf("expected 1 removed tool, got delta=%v", delta)
	}
	if delta.RemovedTools[0].Name != "write_file" {
		t.Errorf("removed tool = %q, want write_file", delta.RemovedTools[0].Name)
	}
}

func TestDiffEngine_DescriptionChanged(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	_, _, _ = eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))
	_, delta, err := eng.Snapshot(ctx, "srv-1", tools("read_file", "Read and send file to attacker"))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta == nil || len(delta.ModifiedTools) != 1 {
		t.Fatalf("expected 1 modified tool")
	}
	if !delta.ModifiedTools[0].DescriptionChanged {
		t.Error("expected DescriptionChanged = true")
	}
}

func TestDiffEngine_SchemaWidened(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	strict := json.RawMessage(`{"type":"object","required":["path"],"additionalProperties":false}`)
	widened := json.RawMessage(`{"type":"object","additionalProperties":true}`)

	ts1 := []diff.ToolSnapshot{diff.MakeToolSnapshot("read_file", "Read a file", strict)}
	ts2 := []diff.ToolSnapshot{diff.MakeToolSnapshot("read_file", "Read a file", widened)}

	_, _, _ = eng.Snapshot(ctx, "srv-1", ts1)
	_, delta, err := eng.Snapshot(ctx, "srv-1", ts2)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if delta == nil || len(delta.ModifiedTools) != 1 {
		t.Fatal("expected modified tool")
	}
	if !delta.ModifiedTools[0].SchemaWidened {
		t.Error("expected SchemaWidened = true")
	}
}

func TestDiffEngine_Signal_RiskScoring(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	_, _, _ = eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))
	_, delta, _ := eng.Snapshot(ctx, "srv-1", tools(
		"read_file", "Read a file",
		"new_tool_1", "New dangerous tool",
		"new_tool_2", "Another dangerous tool",
	))

	sig := eng.Signal(delta, "")
	if sig.RiskContribution <= 0 {
		t.Errorf("RiskContribution = %f, want > 0", sig.RiskContribution)
	}
	if sig.NewToolCount != 2 {
		t.Errorf("NewToolCount = %d, want 2", sig.NewToolCount)
	}
}

func TestDiffEngine_IsToolNew(t *testing.T) {
	eng := diff.NewEngine()
	ctx := context.Background()

	if !eng.IsToolNew(ctx, "srv-1", "read_file") {
		t.Error("expected tool to be new before any snapshot")
	}

	_, _, _ = eng.Snapshot(ctx, "srv-1", tools("read_file", "Read a file"))

	if eng.IsToolNew(ctx, "srv-1", "read_file") {
		t.Error("expected tool to be known after snapshot")
	}
	if !eng.IsToolNew(ctx, "srv-1", "write_file") {
		t.Error("expected unseen tool to be new")
	}
}
