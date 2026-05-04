// Command agent is the MCPIDS endpoint daemon.
// It discovers local MCP server configurations, optionally wraps stdio processes
// behind the inspection pipeline, and reports inventory to the control plane.
//
// Usage:
//
//	agent --config agent.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mcpids/mcpids/internal/agent"
	"github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/config"
	"github.com/mcpids/mcpids/internal/diff"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/gateway"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/policy"
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/internal/risk"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/semantic"
	"github.com/mcpids/mcpids/internal/session"
	pgstore "github.com/mcpids/mcpids/internal/storage/postgres"
	redisclient "github.com/mcpids/mcpids/internal/storage/redis"
	"github.com/mcpids/mcpids/internal/telemetry"
	"github.com/mcpids/mcpids/internal/transport"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		slog.Error("agent: fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfgFile := flag.String("config", "", "path to agent YAML config file")
	flag.Parse()

	// ── Config ──────────────────────────────────────────────────────────────────
	cfg, err := config.LoadAgentConfig(*cfgFile)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// ── Telemetry ───────────────────────────────────────────────────────────────
	ctx := context.Background()
	tel, err := telemetry.Init(ctx, telemetry.Config{
		ServiceName:    cfg.Telemetry.ServiceName,
		ServiceVersion: version,
		OTLPEndpoint:   cfg.Telemetry.OTLPEndpoint,
		PrometheusAddr: cfg.Telemetry.PrometheusAddr,
		LogLevel:       cfg.Telemetry.LogLevel,
		LogFormat:      cfg.Telemetry.LogFormat,
	})
	if err != nil {
		slog.Warn("agent: telemetry init failed (continuing)", "error", err)
	} else {
		defer tel.Shutdown(ctx)
	}
	metricSet, err := telemetry.RegisterMetrics("mcpids/agent")
	if err != nil {
		slog.Warn("agent: metrics registration failed (continuing)", "error", err)
	}

	// ── Control-plane gRPC (preferred service plane) ──────────────────────────
	var policyClient mcpidsv1.PolicyServiceClient
	var inventoryClient mcpidsv1.InventoryServiceClient
	var eventClient mcpidsv1.EventServiceClient
	var approvalClient mcpidsv1.ApprovalServiceClient
	var recorder eventspkg.Recorder
	if cfg.ControlPlane.Address != "" {
		if cpConn, err := transport.DialControlPlane(ctx, cfg.ControlPlane); err != nil {
			slog.Warn("agent: control-plane gRPC unavailable, falling back to local stores", "error", err)
		} else {
			defer cpConn.Close()
			policyClient = mcpidsv1.NewPolicyServiceClient(cpConn)
			inventoryClient = mcpidsv1.NewInventoryServiceClient(cpConn)
			eventClient = mcpidsv1.NewEventServiceClient(cpConn)
			approvalClient = mcpidsv1.NewApprovalServiceClient(cpConn)
			recorder = eventspkg.NewGRPCRecorder(cpConn)
			slog.Info("agent: connected to control-plane gRPC", "addr", cfg.ControlPlane.Address)
		}
	}

	// ── PostgreSQL (optional) ──────────────────────────────────────────────────
	var db *pgstore.DB
	if cfg.Database.URL != "" {
		db, err = pgstore.NewDB(ctx, pgstore.Config{
			URL:             cfg.Database.URL,
			MaxConns:        cfg.Database.MaxConns,
			MinConns:        cfg.Database.MinConns,
			MaxConnLifetime: cfg.Database.MaxConnLifetime,
			MaxConnIdleTime: cfg.Database.MaxConnIdleTime,
		})
		if err != nil {
			slog.Warn("agent: postgres unavailable, using in-memory stores", "error", err)
		} else {
			defer db.Close()
		}
	}

	// ── Redis (optional) ────────────────────────────────────────────────────────
	var redis *redisclient.Client
	if cfg.Redis.URL != "" {
		redis, err = redisclient.NewClient(ctx, redisclient.Config{
			URL:          cfg.Redis.URL,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
			PoolSize:     cfg.Redis.PoolSize,
		})
		if err != nil {
			slog.Warn("agent: redis unavailable, using in-memory session storage", "error", err)
		}
	}

	// ── Session manager ─────────────────────────────────────────────────────────
	sessionManager := session.NewManager(redis)
	if eventClient != nil {
		sessionManager = session.NewManagerWithStore(redis, session.NewGRPCStore(eventClient))
	} else if db != nil {
		sessionManager = session.NewManagerWithStore(redis, session.NewPGStore(db.Pool()))
	}

	// ── Rules engine ────────────────────────────────────────────────────────────
	var rulesEngine rules.Engine
	if policyClient != nil && cfg.TenantID != "" {
		rulesEngine, err = rules.NewEngineWithStore(ctx, nil, rules.NewGRPCStore(policyClient, cfg.TenantID))
	} else if db != nil {
		rulesEngine, err = rules.NewEngineWithStore(ctx, nil, rules.NewPGStore(db.Pool()))
	} else {
		rulesEngine, err = rules.NewEngine(ctx, nil)
	}
	if err != nil {
		return fmt.Errorf("rules engine: %w", err)
	}

	// ── Risk engine ─────────────────────────────────────────────────────────────
	riskEngine := risk.NewEngine(risk.DefaultWeights)

	// ── Semantic classifier ──────────────────────────────────────────────────────
	semanticClassifier, err := semantic.NewClassifier(semantic.Options{
		Provider:       cfg.Semantic.Provider,
		Endpoint:       cfg.Semantic.Endpoint,
		BearerToken:    cfg.Semantic.BearerToken,
		Model:          cfg.Semantic.Model,
		Timeout:        cfg.Semantic.Timeout,
		FallbackToStub: cfg.Semantic.FallbackToStub,
	})
	if err != nil {
		return fmt.Errorf("semantic classifier: %w", err)
	}
	slog.Info("agent: semantic classifier initialized", "provider", semanticClassifier.Name())

	// ── Policy engine ───────────────────────────────────────────────────────────
	policyEngine := policy.NewEngine(policy.Options{
		RulesEngine:    rulesEngine,
		RiskEngine:     riskEngine,
		SemanticEngine: semanticClassifier,
	})

	// ── Diff engine ─────────────────────────────────────────────────────────────
	var diffStore diff.Store
	diffEngine := diff.NewEngine()
	if inventoryClient != nil && cfg.TenantID != "" {
		diffStore = diff.NewGRPCStore(inventoryClient, cfg.TenantID)
		diffEngine = diff.NewEngineWithStore(diffStore)
	} else if db != nil {
		diffStore = diff.NewPGStore(db.Pool(), cfg.TenantID)
		diffEngine = diff.NewEngineWithStore(diffStore)
	}

	// ── Graph + schema engines ─────────────────────────────────────────────────
	graphEngine := graph.NewEngine()
	if eventClient == nil && db != nil {
		graphEngine = graph.NewEngineWithStore(graph.NewPGStore(db.Pool()))
	}
	schemaValidator := schemapkg.NewValidatorWithStore(diffStore)

	// ── Approvals workflow (requires Redis) ─────────────────────────────────────
	var approvalWorkflow approvals.Workflow
	if approvalClient != nil && cfg.TenantID != "" {
		approvalWorkflow = approvals.NewGRPCWorkflow(approvalClient, cfg.TenantID, 0)
	} else if redis != nil {
		if db != nil {
			approvalWorkflow = approvals.NewWorkflowWithStore(redis, &approvals.NoOpNotifier{}, approvals.NewPGStore(db.Pool()), 0)
		} else {
			approvalWorkflow = approvals.NewWorkflow(redis, &approvals.NoOpNotifier{}, 0)
		}
	}

	// ── Agent ───────────────────────────────────────────────────────────────────
	if recorder == nil && db != nil {
		recorder = eventspkg.NewPGRecorder(db.Pool())
	}
	agentOpts := agent.Options{
		Config:          cfg,
		Policy:          policyEngine,
		Diff:            diffEngine,
		Graph:           graphEngine,
		Schema:          schemaValidator,
		Semantic:        semanticClassifier,
		Sessions:        sessionManager,
		Approvals:       approvalWorkflow,
		Recorder:        recorder,
		Metrics:         gateway.NewPipelineMetrics(metricSet),
		InventoryClient: inventoryClient,
	}
	if db != nil {
		agentOpts.DB = db.Pool()
	}
	a := agent.New(agentOpts)

	// ── Signal handling ─────────────────────────────────────────────────────────
	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if policyClient != nil && cfg.TenantID != "" {
		go streamPolicyUpdatesLoop(runCtx, policyClient, cfg.TenantID, cfg.AgentID, rulesEngine, cfg.PolicyRefreshInterval)
	} else {
		go reloadRulesLoop(runCtx, rulesEngine, cfg.PolicyRefreshInterval)
	}

	return a.Run(runCtx)
}

func reloadRulesLoop(ctx context.Context, engine rules.Engine, interval time.Duration) {
	if engine == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := engine.Reload(ctx); err != nil {
				slog.Warn("agent: rules reload failed", "error", err)
			}
		}
	}
}

func streamPolicyUpdatesLoop(ctx context.Context, client mcpidsv1.PolicyServiceClient, tenantID, agentID string, engine rules.Engine, retryInterval time.Duration) {
	if client == nil || engine == nil || tenantID == "" {
		return
	}
	if retryInterval <= 0 {
		retryInterval = 30 * time.Second
	}
	for {
		stream, err := client.StreamPolicyUpdates(ctx, &mcpidsv1.StreamPolicyUpdatesRequest{
			TenantId: tenantID,
			AgentId:  agentID,
		})
		if err != nil {
			slog.Warn("agent: policy stream unavailable, retrying", "error", err)
		} else {
			for {
				_, err := stream.Recv()
				if err != nil {
					if err != io.EOF && ctx.Err() == nil {
						slog.Warn("agent: policy stream interrupted", "error", err)
					}
					break
				}
				if err := engine.Reload(ctx); err != nil {
					slog.Warn("agent: rules reload failed", "error", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}
}
