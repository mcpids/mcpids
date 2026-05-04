package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	approvalspkg "github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/config"
	"github.com/mcpids/mcpids/internal/diff"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/mcp"
	"github.com/mcpids/mcpids/internal/policy"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/semantic"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
	"github.com/mcpids/mcpids/internal/transport"
)

// Gateway is the top-level MCPIDS HTTP gateway.
// It wires all engines and serves the interception reverse proxy.
type Gateway struct {
	cfg      config.GatewayConfig
	pipeline *Pipeline
	proxy    *Proxy
	server   *http.Server
}

// Options configures the Gateway.
type Options struct {
	Config    config.GatewayConfig
	Policy    policy.Engine
	Diff      diff.Engine
	Graph     graph.Engine
	Schema    schemapkg.Validator
	Semantic  semantic.Classifier
	Sessions  sessionpkg.Manager
	Approvals approvalspkg.Workflow
	Recorder  eventspkg.Recorder
	Metrics   *PipelineMetrics
}

// New creates a Gateway with the given options.
// Returns an error if the upstream URL is invalid.
func New(opts Options) (*Gateway, error) {
	upstreamURL, err := url.Parse(opts.Config.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid upstream URL %q: %w", opts.Config.UpstreamURL, err)
	}

	pipeline := NewPipeline(PipelineOptions{
		Policy:          opts.Policy,
		Diff:            opts.Diff,
		Graph:           opts.Graph,
		Schema:          opts.Schema,
		Semantic:        opts.Semantic,
		Sessions:        opts.Sessions,
		Approvals:       opts.Approvals,
		Recorder:        opts.Recorder,
		Metrics:         opts.Metrics,
		MaxEvalDuration: opts.Config.Pipeline.MaxEvalDuration,
		SemanticTimeout: opts.Config.Pipeline.MaxEvalDuration / 2,
		MonitorOnlyMode: opts.Config.Pipeline.MonitorOnlyMode,
		FailOpen:        opts.Config.Pipeline.FailOpen,
	})

	proxy := NewProxy(upstreamURL, pipeline, opts.Config.MaxMessageSize)

	// Build the HTTP router with middleware.
	r := chi.NewRouter()
	r.Use(RecoveryMiddleware)
	r.Use(RequestLogMiddleware)
	r.Use(middleware.RequestID)
	r.Use(SessionMiddleware(
		opts.Sessions,
		opts.Config.TenantID,
		opts.Config.AgentID,
		opts.Config.ServerID,
	))

	// Health check endpoint - bypasses the inspection pipeline.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","component":"gateway","semantic_classifier":%q}`,
			pipeline.SemanticClassifierName())
	})

	// All MCP traffic is handled by the proxy.
	r.HandleFunc("/*", proxy.ServeHTTP)
	r.HandleFunc("/", proxy.ServeHTTP)

	srv := &http.Server{
		Addr:         opts.Config.ListenAddr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // large to accommodate SSE streams
		IdleTimeout:  120 * time.Second,
	}

	return &Gateway{
		cfg:      opts.Config,
		pipeline: pipeline,
		proxy:    proxy,
		server:   srv,
	}, nil
}

// ListenAndServe starts the HTTP server and blocks until ctx is cancelled or a fatal error occurs.
// On context cancellation it performs a graceful 30-second shutdown.
func (g *Gateway) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.server.Addr)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", g.server.Addr, err)
	}
	if tlsCfg, err := transport.ServerTLSConfig(g.cfg.TLS); err != nil {
		ln.Close()
		return fmt.Errorf("gateway: TLS config: %w", err)
	} else if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	slog.Info("gateway: listening",
		"addr", g.server.Addr,
		"upstream", g.cfg.UpstreamURL,
		"tenant", g.cfg.TenantID)

	errCh := make(chan error, 1)
	go func() {
		if err := g.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("gateway: shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return g.server.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// NewStdioGateway creates a StdioProxy that wraps the given subprocess command.
// It creates a synthetic session for the stdio connection.
func NewStdioGateway(cmd []string, opts Options) (*StdioProxy, error) {
	pipeline := NewPipeline(PipelineOptions{
		Policy:          opts.Policy,
		Diff:            opts.Diff,
		Graph:           opts.Graph,
		Schema:          opts.Schema,
		Semantic:        opts.Semantic,
		Sessions:        opts.Sessions,
		Approvals:       opts.Approvals,
		Recorder:        opts.Recorder,
		Metrics:         opts.Metrics,
		MaxEvalDuration: opts.Config.Pipeline.MaxEvalDuration,
		SemanticTimeout: opts.Config.Pipeline.MaxEvalDuration / 2,
		MonitorOnlyMode: opts.Config.Pipeline.MonitorOnlyMode,
		FailOpen:        opts.Config.Pipeline.FailOpen,
	})

	sess := &mcp.Session{
		TenantID:  opts.Config.TenantID,
		AgentID:   opts.Config.AgentID,
		ServerID:  opts.Config.ServerID,
		Transport: "stdio",
		State:     mcp.StateNew,
	}

	if opts.Sessions != nil {
		ctx := context.Background()
		if err := opts.Sessions.Create(ctx, sess); err != nil {
			slog.Warn("gateway: failed to create stdio session", "error", err)
		}
	}

	return NewStdioProxy(cmd, pipeline, sess, opts.Config.ServerID, opts.Config.MaxMessageSize), nil
}
