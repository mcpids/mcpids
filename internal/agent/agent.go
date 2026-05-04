package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	approvalspkg "github.com/mcpids/mcpids/internal/approvals"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcpids/mcpids/internal/config"
	"github.com/mcpids/mcpids/internal/diff"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/gateway"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/policy"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/semantic"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

// Agent is the MCPIDS endpoint daemon.
// It discovers local MCP servers, optionally wraps them as stdio proxies,
// and polls the control plane for policy updates.
type Agent struct {
	cfg        config.AgentConfig
	discoverer *Discoverer
	inventory  *InventoryReporter
	heartbeat  *Heartbeat
	wrapper    *WrapperManager
}

// Options configures the Agent.
type Options struct {
	Config    config.AgentConfig
	Policy    policy.Engine
	Diff      diff.Engine
	Graph     graph.Engine
	Schema    schemapkg.Validator
	Semantic  semantic.Classifier
	Sessions  sessionpkg.Manager
	Approvals approvalspkg.Workflow
	Recorder  eventspkg.Recorder
	Metrics   *gateway.PipelineMetrics
	InventoryClient mcpidsv1.InventoryServiceClient
	DB        *pgxpool.Pool
}

// New creates an Agent with the given options.
func New(opts Options) *Agent {
	discoverer := NewDiscoverer(opts.Config.Discovery.ConfigPaths)
	inventory := NewInventoryReporter(opts.Config.TenantID, opts.Config.AgentID, discoverer, opts.DB, opts.InventoryClient)

	var wrapper *WrapperManager
	if opts.Config.Wrapper.Enabled {
		wrapper = NewWrapperManager(
			opts.Config.TenantID,
			opts.Config.AgentID,
			opts.Config.Wrapper.MaxProcesses,
			opts.Policy,
			opts.Diff,
			opts.Graph,
			opts.Schema,
			opts.Semantic,
			opts.Sessions,
			opts.Approvals,
			opts.Recorder,
			opts.Metrics,
		)
	}

	a := &Agent{
		cfg:        opts.Config,
		discoverer: discoverer,
		inventory:  inventory,
		wrapper:    wrapper,
	}

	// Heartbeat polls for policy updates and re-scans inventory.
	interval := opts.Config.PolicyRefreshInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	a.heartbeat = NewHeartbeat(interval, a.tick)

	return a
}

// Run starts the agent and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	slog.Info("agent: starting",
		"tenant_id", a.cfg.TenantID,
		"agent_id", a.cfg.AgentID,
		"wrapper_enabled", a.cfg.Wrapper.Enabled)

	// Initial inventory scan + optional wrapper launch.
	if err := a.scanAndWrap(ctx); err != nil {
		slog.Warn("agent: initial scan failed", "error", err)
	}

	// Run heartbeat (blocks until ctx cancelled).
	return a.heartbeat.Run(ctx)
}

// tick is called on each heartbeat cycle.
func (a *Agent) tick(ctx context.Context) error {
	// Re-scan local config for new or removed servers.
	if err := a.scanAndWrap(ctx); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	return nil
}

// scanAndWrap discovers local servers and wraps new stdio servers.
func (a *Agent) scanAndWrap(ctx context.Context) error {
	servers, err := a.inventory.Report(ctx)
	if err != nil {
		return err
	}

	if a.wrapper == nil || len(servers) == 0 {
		return nil
	}

	serverIDsByName := make(map[string]string, len(servers))
	for _, server := range servers {
		serverIDsByName[server.Name] = server.ID
	}

	// Discover raw entries to get command info for wrapping.
	entries := a.discoverer.Discover()
	for _, entry := range entries {
		if entry.Transport != "stdio" {
			continue
		}
		serverID, err := a.wrapper.Wrap(ctx, entry, serverIDsByName[entry.Name])
		if err != nil {
			slog.Warn("agent: failed to wrap server",
				"name", entry.Name,
				"error", err)
			continue
		}
		slog.Info("agent: wrapped server", "name", entry.Name, "server_id", serverID)
	}

	return nil
}
