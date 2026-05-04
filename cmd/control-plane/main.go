// Command control-plane is the MCPIDS admin and orchestration server.
// It exposes a REST admin API for operators and a gRPC service plane
// for gateway/agent clients to fetch policies, report inventory, and
// stream detection events.
//
// Usage:
//
//	control-plane --config control-plane.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/config"
	"github.com/mcpids/mcpids/internal/controlplane"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/policy"
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/internal/risk"
	"github.com/mcpids/mcpids/internal/semantic"
	"github.com/mcpids/mcpids/internal/session"
	pgstore "github.com/mcpids/mcpids/internal/storage/postgres"
	redisclient "github.com/mcpids/mcpids/internal/storage/redis"
	"github.com/mcpids/mcpids/internal/telemetry"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		slog.Error("control-plane: fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfgFile := flag.String("config", "", "path to control-plane YAML config file")
	flag.Parse()

	// ── Config ──────────────────────────────────────────────────────────────────
	cfg, err := config.LoadControlPlaneConfig(*cfgFile)
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
		slog.Warn("control-plane: telemetry init failed (continuing)", "error", err)
	} else {
		defer tel.Shutdown(ctx)
	}
	if _, err := telemetry.RegisterMetrics("mcpids/control-plane"); err != nil {
		slog.Warn("control-plane: metrics registration failed (continuing)", "error", err)
	}

	// ── PostgreSQL ──────────────────────────────────────────────────────────────
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
			return fmt.Errorf("postgres: %w", err)
		}
		defer db.Close()
		slog.Info("control-plane: PostgreSQL connected")
	} else {
		slog.Warn("control-plane: no database URL configured, running without persistence")
	}

	// ── Redis ───────────────────────────────────────────────────────────────────
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
			slog.Warn("control-plane: redis unavailable (continuing)", "error", err)
		}
	}

	// ── Session manager ─────────────────────────────────────────────────────────
	sessionManager := session.NewManager(redis)
	if db != nil {
		sessionManager = session.NewManagerWithStore(redis, session.NewPGStore(db.Pool()))
	}

	// ── Rules engine ────────────────────────────────────────────────────────────
	var rulesEngine rules.Engine
	if db != nil {
		rulesEngine, err = rules.NewEngineWithStore(ctx, cfg.Rules.YAMLPaths, rules.NewPGStore(db.Pool()))
	} else {
		rulesEngine, err = rules.NewEngine(ctx, cfg.Rules.YAMLPaths)
	}
	if err != nil {
		return fmt.Errorf("rules engine: %w", err)
	}

	// ── Risk engine ─────────────────────────────────────────────────────────────
	riskEngine := risk.NewEngine(risk.DefaultWeights)

	// ── Semantic classifier ─────────────────────────────────────────────────────
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
	slog.Info("control-plane: semantic classifier initialized", "provider", semanticClassifier.Name())

	// ── Policy engine ───────────────────────────────────────────────────────────
	policyEngine := policy.NewEngine(policy.Options{
		RulesEngine:    rulesEngine,
		RiskEngine:     riskEngine,
		SemanticEngine: semanticClassifier,
	})

	// ── Graph engine ────────────────────────────────────────────────────────────
	graphEngine := graph.NewEngine()
	if db != nil {
		graphEngine = graph.NewEngineWithStore(graph.NewPGStore(db.Pool()))
	}

	// ── Approvals workflow ──────────────────────────────────────────────────────
	var approvalWF approvals.Workflow
	if redis != nil {
		var notifier approvals.Notifier = &approvals.NoOpNotifier{}
		if cfg.Approvals.WebhookURL != "" {
			notifier = approvals.NewWebhookNotifier(cfg.Approvals.WebhookURL, cfg.Approvals.WebhookSecret)
		}
		if db != nil {
			approvalWF = approvals.NewWorkflowWithStore(redis, notifier, approvals.NewPGStore(db.Pool()), cfg.Approvals.DefaultTimeout)
		} else {
			approvalWF = approvals.NewWorkflow(redis, notifier, cfg.Approvals.DefaultTimeout)
		}
	}

	// ── Control plane server ────────────────────────────────────────────────────
	var recorder eventspkg.Recorder
	if db != nil {
		recorder = eventspkg.NewPGRecorder(db.Pool())
	}
	srv := controlplane.New(controlplane.Options{
		Config:         cfg,
		PolicyEngine:   policyEngine,
		RulesEngine:    rulesEngine,
		SessionManager: sessionManager,
		ApprovalWF:     approvalWF,
		GraphEngine:    graphEngine,
		EventRecorder:  recorder,
		DB:             db,
	})

	// ── Signal handling ─────────────────────────────────────────────────────────
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runCtx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	// ── Start servers ───────────────────────────────────────────────────────────
	slog.Info("control-plane: starting",
		"version", version,
		"http_addr", cfg.HTTPListenAddr,
		"grpc_addr", cfg.GRPCListenAddr,
	)

	errCh := make(chan error, 2)
	go func() {
		errCh <- srv.ServeGRPC(runCtx)
	}()
	go func() {
		errCh <- srv.ServeHTTP(runCtx)
	}()

	err = <-errCh
	cancel()
	<-errCh
	return err
}
