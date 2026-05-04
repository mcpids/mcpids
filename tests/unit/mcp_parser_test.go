package unit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mcpids/mcpids/internal/mcp"
)

var parser = mcp.NewParser(mcp.DefaultMaxMessageSize)

func TestParser_ValidRequest(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	msg, err := parser.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if msg.Method != "tools/list" {
		t.Errorf("Method = %q, want tools/list", msg.Method)
	}
	if parser.Kind(msg) != mcp.KindRequest {
		t.Errorf("Kind = %v, want KindRequest", parser.Kind(msg))
	}
}

func TestParser_ValidNotification(t *testing.T) {
	raw := `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`
	msg, err := parser.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if parser.Kind(msg) != mcp.KindNotification {
		t.Errorf("Kind = %v, want KindNotification", parser.Kind(msg))
	}
}

func TestParser_ValidResponse(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	msg, err := parser.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if parser.Kind(msg) != mcp.KindResponse {
		t.Errorf("Kind = %v, want KindResponse", parser.Kind(msg))
	}
}

func TestParser_ValidError(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`
	msg, err := parser.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if parser.Kind(msg) != mcp.KindError {
		t.Errorf("Kind = %v, want KindError", parser.Kind(msg))
	}
}

func TestParser_InvalidVersion(t *testing.T) {
	raw := `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`
	_, err := parser.ParseMessage([]byte(raw))
	if err == nil {
		t.Error("expected error for non-2.0 version")
	}
}

func TestParser_TooLarge(t *testing.T) {
	p := mcp.NewParser(100)
	raw := strings.Repeat("x", 200)
	_, err := p.ParseMessage([]byte(raw))
	if err == nil {
		t.Error("expected error for oversized message")
	}
}

func TestParser_InvalidJSON(t *testing.T) {
	_, err := parser.ParseMessage([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParser_ParseToolsListResult(t *testing.T) {
	result := json.RawMessage(`{"tools":[{"name":"read_file","description":"Read a file","inputSchema":{"type":"object"}}]}`)
	r, err := mcp.ParseToolsListResult(result)
	if err != nil {
		t.Fatalf("ParseToolsListResult: %v", err)
	}
	if len(r.Tools) != 1 {
		t.Errorf("len(Tools) = %d, want 1", len(r.Tools))
	}
	if r.Tools[0].Name != "read_file" {
		t.Errorf("tool name = %q, want read_file", r.Tools[0].Name)
	}
}

func TestParser_ParseToolCallParams_Valid(t *testing.T) {
	params := json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"}}`)
	p, err := mcp.ParseToolCallParams(params)
	if err != nil {
		t.Fatalf("ParseToolCallParams: %v", err)
	}
	if p.Name != "read_file" {
		t.Errorf("Name = %q, want read_file", p.Name)
	}
}

func TestParser_ParseToolCallParams_MissingName(t *testing.T) {
	params := json.RawMessage(`{"arguments":{"path":"/etc/hosts"}}`)
	_, err := mcp.ParseToolCallParams(params)
	if err == nil {
		t.Error("expected error for missing name field")
	}
}

func TestParser_ParseInitializeParams_Valid(t *testing.T) {
	params := json.RawMessage(`{
		"protocolVersion":"2025-11-25",
		"capabilities":{},
		"clientInfo":{"name":"test-client","version":"1.0"}
	}`)
	p, err := mcp.ParseInitializeParams(params)
	if err != nil {
		t.Fatalf("ParseInitializeParams: %v", err)
	}
	if p.ProtocolVersion != "2025-11-25" {
		t.Errorf("ProtocolVersion = %q, want 2025-11-25", p.ProtocolVersion)
	}
}

func TestParser_DenyResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	resp := mcp.DenyResponse(id, "blocked by policy")
	if resp.Error == nil {
		t.Fatal("expected error in deny response")
	}
	if resp.Error.Code != mcp.CodeDeniedByPolicy {
		t.Errorf("code = %d, want %d", resp.Error.Code, mcp.CodeDeniedByPolicy)
	}
}
