// Package agent implements the MCPIDS endpoint agent.
// The agent discovers local MCP servers, wraps stdio processes,
// and reports inventory to the control plane.
package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ServerEntry describes a single MCP server found in a config file.
type ServerEntry struct {
	// Name is the identifier for this server as defined in the config file.
	Name string

	// Command is the executable command (for stdio servers).
	Command []string

	// URL is the HTTP/SSE endpoint (for remote servers).
	URL string

	// Transport is "stdio" or "http".
	Transport string

	// Env holds additional environment variables for the process.
	Env map[string]string

	// SourceFile is the config file this entry was found in.
	SourceFile string
}

// Discoverer scans local MCP configuration files and returns server definitions.
type Discoverer struct {
	paths []string
}

// NewDiscoverer creates a Discoverer that scans the given config file paths.
// Any path may contain a leading "~/" which will be expanded to the home directory.
func NewDiscoverer(paths []string) *Discoverer {
	expanded := make([]string, 0, len(paths))
	home, _ := os.UserHomeDir()
	for _, p := range paths {
		if strings.HasPrefix(p, "~/") && home != "" {
			p = filepath.Join(home, p[2:])
		}
		expanded = append(expanded, p)
	}
	return &Discoverer{paths: expanded}
}

// Discover reads all configured paths and returns all server entries found.
// Errors from individual files are logged and skipped; they do not abort the scan.
func (d *Discoverer) Discover() []ServerEntry {
	var result []ServerEntry
	for _, p := range d.paths {
		entries, err := d.parseFile(p)
		if err != nil {
			slog.Debug("agent: discovery: skipping file", "path", p, "error", err)
			continue
		}
		result = append(result, entries...)
	}
	return result
}

// parseFile dispatches to the appropriate parser based on the filename.
func (d *Discoverer) parseFile(path string) ([]ServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	base := filepath.Base(path)
	switch base {
	case "mcp.json":
		// Cursor / VS Code MCP format
		return parseCursorMCP(path, data)
	case ".claude.json", "claude.json":
		return parseClaudeMCP(path, data)
	case "claude_desktop_config.json":
		return parseClaudeDesktopConfig(path, data)
	default:
		// Attempt generic MCP JSON parse.
		return parseCursorMCP(path, data)
	}
}

// ─── Format parsers ───────────────────────────────────────────────────────────

// cursorMCPFile is the Cursor/VS Code MCP server config format.
// {"mcpServers": {"serverName": {"command": "npx", "args": [...], "env": {...}}}}
type cursorMCPFile struct {
	MCPServers map[string]cursorMCPServer `json:"mcpServers"`
}

type cursorMCPServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

func parseCursorMCP(path string, data []byte) ([]ServerEntry, error) {
	var f cursorMCPFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse cursor mcp: %w", err)
	}

	entries := make([]ServerEntry, 0, len(f.MCPServers))
	for name, srv := range f.MCPServers {
		e := ServerEntry{Name: name, SourceFile: path, Env: srv.Env}
		if srv.URL != "" {
			e.Transport = "http"
			e.URL = srv.URL
		} else if srv.Command != "" {
			e.Transport = "stdio"
			e.Command = append([]string{srv.Command}, srv.Args...)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// claudeMCPFile is the ~/.claude.json format.
// {"projects": {"path": {"mcpServers": {...}}}, "numStartups": 0}
type claudeMCPFile struct {
	Projects map[string]struct {
		MCPServers map[string]cursorMCPServer `json:"mcpServers"`
	} `json:"projects"`
	// Top-level mcpServers (global config)
	MCPServers map[string]cursorMCPServer `json:"mcpServers"`
}

func parseClaudeMCP(path string, data []byte) ([]ServerEntry, error) {
	var f claudeMCPFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse claude.json: %w", err)
	}

	var entries []ServerEntry

	// Global servers
	for name, srv := range f.MCPServers {
		entries = append(entries, serverEntryFromCursor(name, srv, path))
	}

	// Per-project servers
	for _, project := range f.Projects {
		for name, srv := range project.MCPServers {
			entries = append(entries, serverEntryFromCursor(name, srv, path))
		}
	}

	return entries, nil
}

// claudeDesktopConfig is the Claude Desktop app format.
// {"mcpServers": {...}} - same shape as Cursor.
func parseClaudeDesktopConfig(path string, data []byte) ([]ServerEntry, error) {
	return parseCursorMCP(path, data)
}

func serverEntryFromCursor(name string, srv cursorMCPServer, path string) ServerEntry {
	e := ServerEntry{Name: name, SourceFile: path, Env: srv.Env}
	if srv.URL != "" {
		e.Transport = "http"
		e.URL = srv.URL
	} else if srv.Command != "" {
		e.Transport = "stdio"
		e.Command = append([]string{srv.Command}, srv.Args...)
	}
	return e
}
