// Package controlplane implements the MCPIDS control plane component.
// It exposes a REST admin API (chi) and a gRPC service plane for gateway/agent clients.
package controlplane

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/auth"
	"github.com/mcpids/mcpids/internal/config"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/policy"
	"github.com/mcpids/mcpids/internal/policy/rules"
	"github.com/mcpids/mcpids/internal/session"
	pgstore "github.com/mcpids/mcpids/internal/storage/postgres"
	"github.com/mcpids/mcpids/internal/transport"
	"github.com/mcpids/mcpids/pkg/types"
)

//go:embed all:ui
var uiFS embed.FS

// Server is the control plane HTTP/gRPC server.
type Server struct {
	cfg            config.ControlPlaneConfig
	policyEngine   policy.Engine
	rulesEngine    rules.Engine
	sessionManager session.Manager
	approvalWF     approvals.Workflow
	graphEngine    graph.Engine
	eventRecorder  eventspkg.Recorder
	db             *pgstore.DB
	httpServer     *http.Server
}

// Options configures the control plane Server.
type Options struct {
	Config         config.ControlPlaneConfig
	PolicyEngine   policy.Engine
	RulesEngine    rules.Engine
	SessionManager session.Manager
	ApprovalWF     approvals.Workflow
	GraphEngine    graph.Engine
	EventRecorder  eventspkg.Recorder
	DB             *pgstore.DB
}

// New creates a control plane server with the given options.
func New(opts Options) *Server {
	s := &Server{
		cfg:            opts.Config,
		policyEngine:   opts.PolicyEngine,
		rulesEngine:    opts.RulesEngine,
		sessionManager: opts.SessionManager,
		approvalWF:     opts.ApprovalWF,
		graphEngine:    opts.GraphEngine,
		eventRecorder:  opts.EventRecorder,
		db:             opts.DB,
	}

	// ── Auth middleware ──────────────────────────────────────────────────────
	authenticator := auth.NewAuthenticator(opts.Config.Auth)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	// Health (unauthenticated)
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	// Web UI - served from the embedded ui/ directory (unauthenticated, SPA).
	r.Get("/ui", http.RedirectHandler("/ui/", http.StatusMovedPermanently).ServeHTTP)
	r.Get("/ui/*", s.handleUI)

	// API v1 (authenticated when auth is enabled)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authenticator.Middleware())
		r.Use(auth.RequireRoles(opts.Config.Auth.AllowedRoles))

		// Servers
		r.Get("/servers", s.handleListServers)
		r.Post("/servers", s.handleCreateServer)
		r.Get("/servers/{id}", s.handleGetServer)
		r.Get("/servers/{id}/tools", s.handleListServerTools)
		r.Get("/servers/{id}/diffs", s.handleListServerDiffs)

		// Policy & Rules
		r.Get("/policies", s.handleListPolicies)
		r.Post("/policies", s.handleCreatePolicy)
		r.Patch("/policies/{id}", s.handleUpdatePolicy)
		r.Delete("/policies/{id}", s.handleDeletePolicy)
		r.Get("/rules", s.handleListRules)
		r.Post("/rules", s.handleCreateRule)
		r.Patch("/rules/{id}", s.handleUpdateRule)

		// Sessions
		r.Get("/sessions", s.handleListSessions)
		r.Get("/sessions/{id}", s.handleGetSession)
		r.Post("/sessions/{id}/quarantine", s.handleQuarantineSession)

		// Detections & Incidents
		r.Get("/detections", s.handleListDetections)
		r.Get("/incidents", s.handleListIncidents)
		r.Post("/incidents", s.handleCreateIncident)
		r.Patch("/incidents/{id}", s.handleUpdateIncident)
		r.Get("/incidents/{id}/evidence", s.handleListEvidence)

		// Approvals
		r.Get("/approvals", s.handleListApprovals)
		r.Get("/approvals/{id}", s.handleGetApproval)
		r.Post("/approvals/{id}/decide", s.handleDecideApproval)

		// Graph
		r.Get("/graph/sessions/{id}", s.handleGetSessionGraph)
		r.Get("/graph/agents/{id}", s.handleGetAgentGraph)
		r.Get("/graph/agents/{id}/analyze", s.handleAnalyzeAgent)

		// Audit
		r.Get("/audit", s.handleListAudit)

		// Dashboard
		r.Get("/dashboard/summary", s.handleDashboardSummary)
		r.Get("/dashboard/risky-servers", s.handleRiskyServers)
		r.Get("/dashboard/changed-tools", s.handleChangedTools)
		r.Get("/dashboard/pending-approvals", s.handleDashboardPendingApprovals)
	})

	s.httpServer = &http.Server{
		Addr:         opts.Config.HTTPListenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// ServeHTTP starts the REST API server and blocks until ctx is cancelled.
func (s *Server) ServeHTTP(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("control-plane: listen %s: %w", s.httpServer.Addr, err)
	}
	if tlsCfg, err := transport.ServerTLSConfig(s.cfg.TLS); err != nil {
		ln.Close()
		return fmt.Errorf("control-plane: TLS config: %w", err)
	} else if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	slog.Info("control-plane: REST API listening", "addr", s.httpServer.Addr)

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		slog.Info("control-plane: shutting down REST API")
		return s.httpServer.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleUI serves the embedded single-page dashboard from /ui/*.
// The embedded FS has the layout: ui/index.html, so we strip the "ui" prefix.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "ui not available", http.StatusInternalServerError)
		return
	}
	// Strip the /ui prefix so chi wildcard doesn't double-nest.
	path := strings.TrimPrefix(r.URL.Path, "/ui")
	if path == "" || path == "/" {
		path = "/index.html"
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = path
	http.FileServer(http.FS(sub)).ServeHTTP(w, r2)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	status := map[string]string{"status": "ok", "component": "control-plane"}
	if s.db != nil {
		if err := s.db.Ping(r.Context()); err != nil {
			status["database"] = "unhealthy"
			writeJSON(w, http.StatusServiceUnavailable, status)
			return
		}
		status["database"] = "healthy"
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		if err := s.db.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": "database unreachable"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	summary := map[string]any{
		"active_sessions":   0,
		"pending_approvals": 0,
		"recent_incidents":  0,
		"detections_24h":    0,
	}

	if s.db != nil {
		pool := s.db.Pool()
		var activeSessions int
		if tenantID != "" {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE state IN ('initializing', 'ready') AND tenant_id = $1", tenantID).Scan(&activeSessions)
		} else {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE state IN ('initializing', 'ready')").Scan(&activeSessions)
		}
		summary["active_sessions"] = activeSessions

		var pendingApprovals int
		if tenantID != "" {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM approvals WHERE status = 'pending' AND tenant_id = $1", tenantID).Scan(&pendingApprovals)
		} else {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM approvals WHERE status = 'pending'").Scan(&pendingApprovals)
		}
		summary["pending_approvals"] = pendingApprovals

		var recentIncidents int
		if tenantID != "" {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '24 hours' AND tenant_id = $1", tenantID).Scan(&recentIncidents)
		} else {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '24 hours'").Scan(&recentIncidents)
		}
		summary["recent_incidents"] = recentIncidents

		var detections24h int
		if tenantID != "" {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM detections WHERE created_at > NOW() - INTERVAL '24 hours' AND tenant_id = $1", tenantID).Scan(&detections24h)
		} else {
			_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM detections WHERE created_at > NOW() - INTERVAL '24 hours'").Scan(&detections24h)
		}
		summary["detections_24h"] = detections24h
	}

	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleRiskyServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}, "total": 0})
		return
	}

	query := `SELECT id, tenant_id, name, COALESCE(url, ''), transport, trust_score, status, first_seen_at, last_seen_at
		 FROM mcp_servers WHERE trust_score < 0.5`
	args := []any{}
	if tenantID != "" {
		query += " AND tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY trust_score ASC LIMIT 20"

	rows, err := s.db.Pool().Query(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	servers := collectServerRows(rows)
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers, "total": len(servers)})
}

func (s *Server) handleChangedTools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tools": []any{}, "total": 0})
		return
	}

	query := `SELECT DISTINCT ON (ts.server_id)
			 ts.id::text, ts.server_id::text, ts.checksum, ts.captured_at, ts.payload
		 FROM tool_snapshots ts
		 WHERE ts.captured_at > NOW() - INTERVAL '24 hours'
		   AND ts.server_id IN (
			 SELECT server_id
			 FROM tool_snapshots
			 WHERE captured_at > NOW() - INTERVAL '24 hours'
			 GROUP BY server_id
			 HAVING COUNT(DISTINCT checksum) > 1
		   )
`
	args := []any{}
	if tenantID != "" {
		query += " AND ts.tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY ts.server_id, ts.captured_at DESC LIMIT 50"

	rows, err := s.db.Pool().Query(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var tools []map[string]any
	for rows.Next() {
		var id, serverID, checksum string
		var capturedAt time.Time
		var payload json.RawMessage
		if err := rows.Scan(&id, &serverID, &checksum, &capturedAt, &payload); err != nil {
			continue
		}
		tools = append(tools, map[string]any{
			"id": id, "server_id": serverID, "checksum": checksum,
			"snapshot_at": capturedAt, "payload": payload,
		})
	}
	if tools == nil {
		tools = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools, "total": len(tools)})
}

func (s *Server) handleDashboardPendingApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"approvals": []any{}, "total": 0})
		return
	}

	query := `SELECT id::text, tenant_id::text,
			 COALESCE(agent_id::text, ''), COALESCE(session_id::text, ''),
			 COALESCE(server_id::text, ''), COALESCE(tool_name, ''),
			 status, created_at, expires_at
		 FROM approvals WHERE status = 'pending'`
	args := []any{}
	if tenantID != "" {
		query += " AND tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY created_at ASC LIMIT 50"

	rows, err := s.db.Pool().Query(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var apprs []map[string]any
	for rows.Next() {
		var id, tenantID, agentID, sessionID, serverID, toolName, status string
		var createdAt, expiresAt time.Time
		if err := rows.Scan(&id, &tenantID, &agentID, &sessionID, &serverID, &toolName, &status, &createdAt, &expiresAt); err != nil {
			continue
		}
		apprs = append(apprs, map[string]any{
			"id": id, "tenant_id": tenantID, "agent_id": agentID, "session_id": sessionID,
			"server_id": serverID, "tool_name": toolName, "status": status,
			"created_at": createdAt, "expires_at": expiresAt,
		})
	}
	if apprs == nil {
		apprs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": apprs, "total": len(apprs)})
}

// ─── Servers ────────────────────────────────────────────────────────────────

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}, "total": 0})
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")
	var err error
	tenantID, err = scopedTenantID(r, tenantID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	limit, offset := parsePagination(r)

	query := `SELECT id, tenant_id, name, COALESCE(url, ''), transport, trust_score, status, first_seen_at, last_seen_at
		 FROM mcp_servers`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.db.Pool().Query(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	servers := collectServerRows(rows)
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers, "total": len(servers)})
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID   string  `json:"tenant_id"`
		Name       string  `json:"name"`
		URL        string  `json:"url"`
		Transport  string  `json:"transport"`
		TrustScore float64 `json:"trust_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tenantID, err := scopedTenantID(r, body.TenantID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	body.TenantID = tenantID
	if body.Name == "" || body.TenantID == "" {
		writeError(w, http.StatusBadRequest, "name and tenant_id are required")
		return
	}
	if body.Transport == "" {
		body.Transport = "http"
	}
	if body.TrustScore == 0 {
		body.TrustScore = 0.5 // default trust
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	var id string
	err = s.db.Pool().QueryRow(r.Context(),
		`INSERT INTO mcp_servers (tenant_id, name, url, transport, trust_score, status)
		 VALUES ($1, $2, $3, $4, $5, 'active') RETURNING id`,
		body.TenantID, body.Name, body.URL, body.Transport, body.TrustScore,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create server")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "created"})
	s.recordAudit(r, body.TenantID, "server.created", "server", id, map[string]any{
		"name":      body.Name,
		"transport": body.Transport,
	})
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	var srv map[string]any
	var name, tenantID, url, transport, status string
	var trustScore float64
	var firstSeen, lastSeen time.Time
	query := `SELECT id, tenant_id, name, COALESCE(url, ''), transport, trust_score, status, first_seen_at, last_seen_at
		 FROM mcp_servers WHERE id = $1`
	args := []any{id}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}
	err = s.db.Pool().QueryRow(r.Context(), query, args...).Scan(&id, &tenantID, &name, &url, &transport, &trustScore, &status, &firstSeen, &lastSeen)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	srv = map[string]any{
		"id": id, "tenant_id": tenantID, "name": name, "url": url,
		"transport": transport, "trust_score": trustScore, "status": status,
		"first_seen_at": firstSeen, "last_seen_at": lastSeen,
	}
	writeJSON(w, http.StatusOK, srv)
}

func (s *Server) handleListServerTools(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tools": []any{}, "total": 0})
		return
	}

	query := `SELECT server_id, name, description, input_schema, is_destructive, is_read_only
		 FROM tools WHERE server_id = $1`
	args := []any{serverID}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}
	query += " ORDER BY name"

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var tools []map[string]any
	for rows.Next() {
		var srvID, toolName, desc string
		var schema json.RawMessage
		var isDestructive, isReadOnly bool
		if err := rows.Scan(&srvID, &toolName, &desc, &schema, &isDestructive, &isReadOnly); err != nil {
			continue
		}
		tools = append(tools, map[string]any{
			"server_id": srvID, "name": toolName, "description": desc,
			"input_schema": schema, "is_destructive": isDestructive, "is_read_only": isReadOnly,
		})
	}
	if tools == nil {
		tools = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools, "total": len(tools)})
}

func (s *Server) handleListServerDiffs(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"diffs": []any{}, "total": 0})
		return
	}

	query := `SELECT id::text, server_id::text, checksum, captured_at, payload
		 FROM tool_snapshots WHERE server_id = $1`
	args := []any{serverID}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}
	query += " ORDER BY captured_at DESC LIMIT 100"

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var diffs []map[string]any
	for rows.Next() {
		var id, srvID, checksum string
		var capturedAt time.Time
		var payload json.RawMessage
		if err := rows.Scan(&id, &srvID, &checksum, &capturedAt, &payload); err != nil {
			continue
		}
		diffs = append(diffs, map[string]any{
			"id": id, "server_id": srvID, "checksum": checksum,
			"snapshot_at": capturedAt, "payload": payload,
		})
	}
	if diffs == nil {
		diffs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"diffs": diffs, "total": len(diffs)})
}

// ─── Policies ───────────────────────────────────────────────────────────────

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"policies": []any{}, "total": 0})
		return
	}

	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	query := `SELECT id::text, tenant_id::text, name, COALESCE(description, ''),
			 is_dry_run, created_at, updated_at
		 FROM policies`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var policies []map[string]any
	for rows.Next() {
		var id, tenantID, name, desc string
		var isDryRun bool
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &tenantID, &name, &desc, &isDryRun, &createdAt, &updatedAt); err != nil {
			continue
		}
		mode := "enforce"
		if isDryRun {
			mode = "monitor_only"
		}
		policies = append(policies, map[string]any{
			"id": id, "tenant_id": tenantID, "name": name, "description": desc,
			"mode": mode, "created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if policies == nil {
		policies = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string `json:"tenant_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Mode        string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tenantID, err := scopedTenantID(r, body.TenantID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	body.TenantID = tenantID
	if body.Name == "" || body.TenantID == "" {
		writeError(w, http.StatusBadRequest, "name and tenant_id are required")
		return
	}
	if body.Mode == "" {
		body.Mode = "enforce"
	}
	isDryRun := body.Mode == "monitor_only" || body.Mode == "dry_run"

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	var id string
	err = s.db.Pool().QueryRow(r.Context(),
		`INSERT INTO policies (tenant_id, name, description, is_dry_run)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		body.TenantID, body.Name, body.Description, isDryRun,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "created"})
	s.recordAudit(r, body.TenantID, "policy.created", "policy", id, map[string]any{
		"name": body.Name,
		"mode": body.Mode,
	})
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	// Build a dynamic UPDATE query from provided fields.
	if rawMode, ok := body["mode"]; ok {
		mode, _ := rawMode.(string)
		body["is_dry_run"] = mode == "monitor_only" || mode == "dry_run"
		delete(body, "mode")
	}
	setClauses, args := buildUpdateClauses(body, []string{"name", "description", "is_dry_run", "is_active", "priority", "default_decision"})
	if len(setClauses) == 0 {
		writeError(w, http.StatusBadRequest, "no valid fields to update")
		return
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE policies SET %s, updated_at = NOW() WHERE id = $%d",
		strings.Join(setClauses, ", "), len(args))
	if tenantFilter != "" {
		args = append(args, tenantFilter)
		query += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}

	tag, err := s.db.Pool().Exec(r.Context(), query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
	s.recordAudit(r, "", "policy.updated", "policy", id, map[string]any{"fields": body})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	query := "DELETE FROM policies WHERE id = $1"
	args := []any{id}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}

	tag, err := s.db.Pool().Exec(r.Context(), query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
	s.recordAudit(r, "", "policy.deleted", "policy", id, nil)
}

// ─── Rules ──────────────────────────────────────────────────────────────────

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}, "total": 0})
		return
	}

	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	query := `SELECT id::text, tenant_id::text, name, COALESCE(description, ''), scope,
			 conditions, COALESCE(any_of, '[]'::jsonb), action, priority,
			 severity, enabled, source, created_at
		 FROM rules`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += " ORDER BY priority ASC LIMIT 200"

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var ruleList []map[string]any
	for rows.Next() {
		var id, tenantID, name, description, severity, source string
		var scope, conditions, anyOf, action json.RawMessage
		var priority int
		var enabled bool
		var createdAt time.Time
		if err := rows.Scan(&id, &tenantID, &name, &description, &scope, &conditions, &anyOf, &action, &priority, &severity, &enabled, &source, &createdAt); err != nil {
			continue
		}
		ruleList = append(ruleList, map[string]any{
			"id": id, "tenant_id": tenantID, "name": name, "description": description,
			"scope": scope, "conditions": conditions, "any_of": anyOf, "action": action,
			"priority": priority, "severity": severity, "enabled": enabled,
			"source": source, "created_at": createdAt,
		})
	}
	if ruleList == nil {
		ruleList = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": ruleList, "total": len(ruleList)})
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string              `json:"tenant_id"`
		PolicyID    string              `json:"policy_id"`
		Name        string              `json:"name"`
		Description string              `json:"description"`
		Scope       rules.RuleScope     `json:"scope"`
		Conditions  []rules.Condition   `json:"conditions"`
		AnyOf       [][]rules.Condition `json:"any_of"`
		Action      json.RawMessage     `json:"action"`
		Priority    int                 `json:"priority"`
		Severity    string              `json:"severity"`
		Enabled     *bool               `json:"enabled"`
		Tags        []string            `json:"tags"`
		TriggerType string              `json:"trigger_type"`
		ActionText  string              `json:"action_text"`
		Pattern     string              `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tenantID, err := scopedTenantID(r, body.TenantID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	body.TenantID = tenantID
	if body.TenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if len(body.Conditions) == 0 && body.TriggerType != "" {
		cond := rules.Condition{Field: "tool.description", Op: rules.ConditionOp(body.TriggerType)}
		if body.Pattern != "" {
			cond.Value = body.Pattern
		}
		body.Conditions = []rules.Condition{cond}
	}
	ruleAction, err := decodeRuleAction(body.Action, body.ActionText)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if ruleAction.Decision == "" {
		writeError(w, http.StatusBadRequest, "action.decision is required")
		return
	}
	if body.Name == "" {
		body.Name = "custom-rule"
	}
	if body.Severity == "" {
		body.Severity = string(types.SeverityMedium)
	}
	if body.Priority == 0 {
		body.Priority = 100
	}
	if body.Enabled == nil {
		enabled := true
		body.Enabled = &enabled
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	scopeJSON, err := json.Marshal(body.Scope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	conditionsJSON, err := json.Marshal(body.Conditions)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conditions")
		return
	}
	anyOfJSON, err := json.Marshal(body.AnyOf)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid any_of")
		return
	}
	actionJSON, err := json.Marshal(ruleAction)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid action")
		return
	}

	var id string
	err = s.db.Pool().QueryRow(r.Context(),
		`INSERT INTO rules (
			 tenant_id, policy_id, name, description, enabled, priority,
			 scope, conditions, any_of, action, severity, tags, source
		 )
		 VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'db')
		 RETURNING id`,
		body.TenantID, body.PolicyID, body.Name, body.Description, *body.Enabled,
		body.Priority, scopeJSON, conditionsJSON, anyOfJSON, actionJSON, body.Severity, body.Tags,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create rule")
		return
	}

	// Trigger a rules engine reload.
	if s.rulesEngine != nil {
		if err := s.rulesEngine.Reload(r.Context()); err != nil {
			slog.Warn("control-plane: rules reload after create failed", "error", err)
		}
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "created"})
	s.recordAudit(r, body.TenantID, "rule.created", "rule", id, map[string]any{
		"name":     body.Name,
		"severity": body.Severity,
	})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	if rawMode, ok := body["action_text"]; ok {
		if mode, ok := rawMode.(string); ok && mode != "" {
			decisionJSON, _ := json.Marshal(rules.RuleAction{Decision: policyDecision(mode)})
			body["action"] = json.RawMessage(decisionJSON)
		}
		delete(body, "action_text")
	}
	if rawScope, ok := body["scope"]; ok {
		if marshaled, err := json.Marshal(rawScope); err == nil {
			body["scope"] = json.RawMessage(marshaled)
		}
	}
	if rawConds, ok := body["conditions"]; ok {
		if marshaled, err := json.Marshal(rawConds); err == nil {
			body["conditions"] = json.RawMessage(marshaled)
		}
	}
	if rawAnyOf, ok := body["any_of"]; ok {
		if marshaled, err := json.Marshal(rawAnyOf); err == nil {
			body["any_of"] = json.RawMessage(marshaled)
		}
	}
	if rawAction, ok := body["action"]; ok {
		if marshaled, err := json.Marshal(rawAction); err == nil {
			ruleAction, err := decodeRuleAction(marshaled, "")
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			normalizedAction, _ := json.Marshal(ruleAction)
			body["action"] = json.RawMessage(normalizedAction)
		}
	}

	setClauses, args := buildUpdateClauses(body, []string{
		"name", "description", "enabled", "priority",
		"scope", "conditions", "any_of", "action",
		"severity", "tags", "policy_id",
	})
	if len(setClauses) == 0 {
		writeError(w, http.StatusBadRequest, "no valid fields to update")
		return
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE rules SET %s, updated_at = NOW() WHERE id = $%d",
		strings.Join(setClauses, ", "), len(args))
	if tenantFilter != "" {
		args = append(args, tenantFilter)
		query += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}

	tag, err := s.db.Pool().Exec(r.Context(), query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	if s.rulesEngine != nil {
		_ = s.rulesEngine.Reload(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
	s.recordAudit(r, "", "rule.updated", "rule", id, map[string]any{"fields": body})
}

// ─── Sessions ───────────────────────────────────────────────────────────────

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}, "total": 0})
		return
	}

	limit, offset := parsePagination(r)
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	query := `SELECT id::text, tenant_id::text, agent_id::text,
			 COALESCE(mcp_server_id::text, ''), state, started_at,
			 COALESCE(quarantined_at, ended_at, started_at)
		 FROM sessions`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.db.Pool().Query(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var sessions []map[string]any
	for rows.Next() {
		var id, tenantID, agentID, serverID, state string
		var startedAt, lastSeen time.Time
		if err := rows.Scan(&id, &tenantID, &agentID, &serverID, &state, &startedAt, &lastSeen); err != nil {
			continue
		}
		sessions = append(sessions, map[string]any{
			"id": id, "tenant_id": tenantID, "agent_id": agentID,
			"server_id": serverID, "state": state,
			"started_at": startedAt, "last_seen_at": lastSeen,
		})
	}
	if sessions == nil {
		sessions = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "total": len(sessions)})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	var tenantID, agentID, serverID, state string
	var startedAt, lastSeen time.Time
	query := `SELECT id::text, tenant_id::text, agent_id::text,
			 COALESCE(mcp_server_id::text, ''), state, started_at,
			 COALESCE(quarantined_at, ended_at, started_at)
		 FROM sessions WHERE id = $1`
	args := []any{id}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}

	err = s.db.Pool().QueryRow(r.Context(), query, args...).Scan(&id, &tenantID, &agentID, &serverID, &state, &startedAt, &lastSeen)
	if err != nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "tenant_id": tenantID, "agent_id": agentID,
		"server_id": serverID, "state": state,
		"started_at": startedAt, "last_seen_at": lastSeen,
	})
}

func (s *Server) handleQuarantineSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Reason == "" {
		body.Reason = "manual quarantine via admin API"
	}

	if tenantFilter != "" {
		sess, err := s.sessionManager.Get(r.Context(), sessionID)
		if err != nil || sess == nil || sess.TenantID != tenantFilter {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
	}

	if err := s.sessionManager.Quarantine(r.Context(), sessionID, body.Reason); err != nil {
		slog.Warn("control-plane: quarantine session failed", "session", sessionID, "error", err)
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	// Also update in DB if available.
	if s.db != nil {
		query := "UPDATE sessions SET state = 'quarantined' WHERE id = $1"
		args := []any{sessionID}
		if tenantFilter != "" {
			query += " AND tenant_id = $2"
			args = append(args, tenantFilter)
		}
		_, _ = s.db.Pool().Exec(r.Context(), query, args...)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "quarantined", "session_id": sessionID})
	s.recordAudit(r, "", "session.quarantined", "session", sessionID, map[string]any{"reason": body.Reason})
}

// ─── Detections & Incidents ─────────────────────────────────────────────────

func (s *Server) handleListDetections(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"detections": []any{}, "total": 0})
		return
	}

	limit, offset := parsePagination(r)
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	query := `SELECT id::text, tenant_id::text,
			 COALESCE(session_id::text, ''), COALESCE(call_id::text, ''),
			 decision, severity, risk_score, created_at
		 FROM detections`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var detections []map[string]any
	for rows.Next() {
		var id, tenantID, sessionID, callID, decision, severity string
		var riskScore float64
		var createdAt time.Time
		if err := rows.Scan(&id, &tenantID, &sessionID, &callID, &decision, &severity, &riskScore, &createdAt); err != nil {
			continue
		}
		detections = append(detections, map[string]any{
			"id": id, "tenant_id": tenantID, "session_id": sessionID,
			"call_id": callID, "decision": decision, "severity": severity,
			"risk_score": riskScore, "created_at": createdAt,
		})
	}
	if detections == nil {
		detections = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"detections": detections, "total": len(detections)})
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"incidents": []any{}, "total": 0})
		return
	}

	limit, offset := parsePagination(r)
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	query := `SELECT id::text, tenant_id::text, array_to_json(session_ids),
			 severity, status, title, created_at
		 FROM incidents`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var incidents []map[string]any
	for rows.Next() {
		var id, tenantID, severity, status, title string
		var sessionIDs json.RawMessage
		var createdAt time.Time
		if err := rows.Scan(&id, &tenantID, &sessionIDs, &severity, &status, &title, &createdAt); err != nil {
			continue
		}
		incidents = append(incidents, map[string]any{
			"id": id, "tenant_id": tenantID, "session_ids": sessionIDs,
			"severity": severity, "status": status, "title": title, "created_at": createdAt,
		})
	}
	if incidents == nil {
		incidents = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": incidents, "total": len(incidents)})
}

func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID  string `json:"tenant_id"`
		SessionID string `json:"session_id"`
		Severity  string `json:"severity"`
		Title     string `json:"title"`
		Notes     string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tenantID, err := scopedTenantID(r, body.TenantID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	body.TenantID = tenantID
	if body.TenantID == "" || body.Title == "" {
		writeError(w, http.StatusBadRequest, "tenant_id and title are required")
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	var id string
	err = s.db.Pool().QueryRow(r.Context(),
		`INSERT INTO incidents (tenant_id, session_ids, severity, status, title, notes)
		 VALUES ($1, ARRAY_REMOVE(ARRAY[NULLIF($2, '')::uuid], NULL), $3, 'open', $4, $5)
		 RETURNING id`,
		body.TenantID, body.SessionID, body.Severity, body.Title, body.Notes,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create incident")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "created"})
	s.recordAudit(r, body.TenantID, "incident.created", "incident", id, map[string]any{
		"title":    body.Title,
		"severity": body.Severity,
	})
}

func (s *Server) handleUpdateIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	setClauses, args := buildUpdateClauses(body, []string{"severity", "status", "title", "notes", "resolved_at"})
	if len(setClauses) == 0 {
		writeError(w, http.StatusBadRequest, "no valid fields to update")
		return
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE incidents SET %s WHERE id = $%d",
		strings.Join(setClauses, ", "), len(args))
	if tenantFilter != "" {
		args = append(args, tenantFilter)
		query += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}

	tag, err := s.db.Pool().Exec(r.Context(), query, args...)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
	s.recordAudit(r, "", "incident.updated", "incident", id, map[string]any{"fields": body})
}

func (s *Server) handleListEvidence(w http.ResponseWriter, r *http.Request) {
	incidentID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"evidence": []any{}, "total": 0})
		return
	}

	var description, notes string
	var detectionIDs, sessionIDs, serverIDs json.RawMessage
	var createdAt time.Time
	query := `SELECT COALESCE(description, ''), COALESCE(notes, ''),
			 array_to_json(detection_ids), array_to_json(session_ids),
			 array_to_json(server_ids), created_at
		 FROM incidents WHERE id = $1`
	args := []any{incidentID}
	if tenantFilter != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantFilter)
	}

	err = s.db.Pool().QueryRow(r.Context(), query, args...).Scan(&description, &notes, &detectionIDs, &sessionIDs, &serverIDs, &createdAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}

	evidence := []map[string]any{
		{
			"incident_id":   incidentID,
			"kind":          "summary",
			"description":   description,
			"notes":         notes,
			"detection_ids": detectionIDs,
			"session_ids":   sessionIDs,
			"server_ids":    serverIDs,
			"created_at":    createdAt,
		},
	}
	writeJSON(w, http.StatusOK, map[string]any{"evidence": evidence, "total": len(evidence)})
}

// ─── Approvals ──────────────────────────────────────────────────────────────

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	// Try DB first, fall back to workflow.
	if s.db != nil {
		limit, offset := parsePagination(r)
		tenantFilter, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
		if err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		query := `SELECT id::text, tenant_id::text,
				 COALESCE(agent_id::text, ''), COALESCE(session_id::text, ''),
				 COALESCE(server_id::text, ''), COALESCE(tool_name, ''),
				 status, created_at, expires_at
				 FROM approvals`
		var args []any
		if tenantFilter != "" {
			query += " WHERE tenant_id = $1"
			args = append(args, tenantFilter)
		}
		query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", limit, offset)

		rows, err := s.db.Pool().Query(r.Context(), query, args...)
		if err == nil {
			defer rows.Close()
			var apprs []map[string]any
			for rows.Next() {
				var id, tenantID, agentID, sessionID, serverID, toolName, status string
				var createdAt, expiresAt time.Time
				if err := rows.Scan(&id, &tenantID, &agentID, &sessionID, &serverID, &toolName, &status, &createdAt, &expiresAt); err != nil {
					continue
				}
				apprs = append(apprs, map[string]any{
					"id": id, "tenant_id": tenantID, "agent_id": agentID, "session_id": sessionID,
					"server_id": serverID, "tool_name": toolName, "status": status,
					"created_at": createdAt, "expires_at": expiresAt,
				})
			}
			if apprs == nil {
				apprs = []map[string]any{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"approvals": apprs, "total": len(apprs)})
			return
		}
	}

	// Fallback to workflow.
	if s.approvalWF == nil {
		writeJSON(w, http.StatusOK, map[string]any{"approvals": []any{}, "total": 0})
		return
	}
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	pending, err := s.approvalWF.ListPending(r.Context(), tenantID, 50, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list approvals")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approvals": pending,
		"total":     len(pending),
	})
}

func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.approvalWF == nil {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	req, err := s.approvalWF.Get(r.Context(), id)
	if err != nil || req == nil {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	if tenantID, err := scopedTenantID(r, req.TenantID); err != nil || (tenantID != "" && req.TenantID != "" && tenantID != req.TenantID) {
		writeError(w, http.StatusForbidden, "approval not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.approvalWF == nil {
		writeError(w, http.StatusServiceUnavailable, "approval workflow not configured")
		return
	}

	var body struct {
		Status    string `json:"status"`    // "approved" | "denied"
		DecidedBy string `json:"decided_by"`
		Notes     string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Status != "approved" && body.Status != "denied" {
		writeError(w, http.StatusBadRequest, "status must be 'approved' or 'denied'")
		return
	}
	if body.DecidedBy == "" {
		// Try to extract from auth claims.
		claims := auth.ClaimsFromContext(r.Context())
		if claims != nil && claims.Subject != "" {
			body.DecidedBy = claims.Subject
		} else {
			writeError(w, http.StatusBadRequest, "decided_by is required")
			return
		}
	}

	if tenantFilter, err := scopedTenantID(r, ""); err == nil && tenantFilter != "" {
		req, err := s.approvalWF.Get(r.Context(), id)
		if err != nil || req == nil || req.TenantID != tenantFilter {
			writeError(w, http.StatusNotFound, "approval not found")
			return
		}
	} else if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	dec := &approvals.Decision{
		RequestID: id,
		Status:    approvals.Status(body.Status),
		DecidedBy: body.DecidedBy,
		Notes:     body.Notes,
	}
	if err := s.approvalWF.Decide(r.Context(), dec); err != nil {
		slog.Warn("control-plane: decide approval failed", "id", id, "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":     body.Status,
		"request_id": id,
	})
	s.recordAudit(r, "", "approval.decided", "approval", id, map[string]any{
		"status": body.Status,
		"notes":  body.Notes,
	})
}

// ─── Graph ──────────────────────────────────────────────────────────────────

func (s *Server) handleGetSessionGraph(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.graphEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}

	nodes, edges, err := s.graphEngine.GetSessionGraph(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "graph query failed")
		return
	}
	nodes, edges = filterGraphByTenant(nodes, edges, tenantFilter)

	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

func (s *Server) handleGetAgentGraph(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantFilter, err := scopedTenantID(r, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.graphEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	nodes, edges, err := s.graphEngine.GetAgentGraph(r.Context(), agentID, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "graph query failed")
		return
	}
	nodes, edges = filterGraphByTenant(nodes, edges, tenantFilter)

	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

func (s *Server) handleAnalyzeAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.graphEngine == nil {
		writeJSON(w, http.StatusOK, &graph.AgentSignal{})
		return
	}
	sig, err := s.graphEngine.AnalyzeAgent(r.Context(), tenantID, agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent analysis failed")
		return
	}
	writeJSON(w, http.StatusOK, sig)
}

// ─── Audit ──────────────────────────────────────────────────────────────────

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}, "total": 0})
		return
	}

	limit, offset := parsePagination(r)
	tenantID, err := scopedTenantID(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	query := `SELECT id::text, tenant_id::text,
			 actor_kind || ':' || COALESCE(actor_id::text, 'system'),
			 action, COALESCE(resource_kind, ''), COALESCE(resource_id::text, ''), created_at
		 FROM audit_events`
	args := []any{}
	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := s.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var entries []map[string]any
	for rows.Next() {
		var id, tenantID, actor, action, resType, resID string
		var createdAt time.Time
		if err := rows.Scan(&id, &tenantID, &actor, &action, &resType, &resID, &createdAt); err != nil {
			continue
		}
		entries = append(entries, map[string]any{
			"id": id, "tenant_id": tenantID, "actor": actor, "action": action,
			"resource_type": resType, "resource_id": resID, "created_at": createdAt,
		})
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": len(entries)})
}

// ─── Middleware + helpers ─────────────────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func scopedTenantID(r *http.Request, requested string) (string, error) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.TenantID == "" {
		return requested, nil
	}
	if requested != "" && requested != claims.TenantID {
		return "", fmt.Errorf("tenant_id does not match token claims")
	}
	return claims.TenantID, nil
}

func (s *Server) recordAudit(r *http.Request, tenantID, action, resourceKind, resourceID string, payload map[string]any) {
	if s.eventRecorder == nil {
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if claims != nil {
		if tenantID == "" {
			tenantID = claims.TenantID
		}
	}
	if tenantID == "" {
		return
	}

	actorKind := "system"
	actorID := ""
	if claims != nil && claims.Subject != "" {
		actorKind = "user"
		if _, err := uuid.Parse(claims.Subject); err == nil {
			actorID = claims.Subject
		}
	}
	ipAddress := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ipAddress = host
	}

	if err := s.eventRecorder.RecordAudit(r.Context(), eventspkg.AuditRecord{
		TenantID:     tenantID,
		ActorID:      actorID,
		ActorKind:    actorKind,
		Action:       action,
		ResourceKind: resourceKind,
		ResourceID:   resourceID,
		Payload:      payload,
		IPAddress:    ipAddress,
	}); err != nil {
		slog.Warn("control-plane: audit write failed", "action", action, "resource", resourceID, "error", err)
	}
}

// parsePagination extracts limit and offset from query params.
func parsePagination(r *http.Request) (limit, offset int) {
	limit = 50  // default
	offset = 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := fmt.Sscanf(l, "%d", &limit); n == 1 && err == nil {
			if limit > 200 {
				limit = 200
			}
			if limit < 1 {
				limit = 1
			}
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	return
}

// buildUpdateClauses builds SET clauses for a PATCH endpoint from a JSON body.
// Only keys that appear in allowedFields are included.
func buildUpdateClauses(body map[string]any, allowedFields []string) ([]string, []any) {
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}

	var setClauses []string
	var args []any
	i := 1
	for key, val := range body {
		if !allowed[key] {
			continue
		}
		if key == "policy_id" {
			if s, ok := val.(string); ok && strings.TrimSpace(s) == "" {
				val = nil
			}
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", key, i))
		args = append(args, val)
		i++
	}
	return setClauses, args
}

// collectServerRows scans pgx rows into server maps. Caller must defer rows.Close().
func collectServerRows(rows pgx.Rows) []map[string]any {
	var servers []map[string]any
	for rows.Next() {
		var id, tenantID, name, url, transport, status string
		var trustScore float64
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&id, &tenantID, &name, &url, &transport, &trustScore, &status, &firstSeen, &lastSeen); err != nil {
			continue
		}
		servers = append(servers, map[string]any{
			"id": id, "tenant_id": tenantID, "name": name, "url": url,
			"transport": transport, "trust_score": trustScore, "status": status,
			"first_seen_at": firstSeen, "last_seen_at": lastSeen,
		})
	}
	if servers == nil {
		servers = []map[string]any{}
	}
	return servers
}

func filterGraphByTenant(nodes []graph.Node, edges []graph.Edge, tenantID string) ([]graph.Node, []graph.Edge) {
	if tenantID == "" {
		return nodes, edges
	}
	filteredNodes := make([]graph.Node, 0, len(nodes))
	for _, node := range nodes {
		if node.TenantID == tenantID {
			filteredNodes = append(filteredNodes, node)
		}
	}
	filteredEdges := make([]graph.Edge, 0, len(edges))
	for _, edge := range edges {
		if edge.TenantID == tenantID {
			filteredEdges = append(filteredEdges, edge)
		}
	}
	return filteredNodes, filteredEdges
}

func policyDecision(decision string) types.Decision {
	switch strings.ToLower(decision) {
	case string(types.DecisionDeny):
		return types.DecisionDeny
	case string(types.DecisionRequireApproval):
		return types.DecisionRequireApproval
	case string(types.DecisionRedact):
		return types.DecisionRedact
	case string(types.DecisionHide):
		return types.DecisionHide
	case string(types.DecisionQuarantine):
		return types.DecisionQuarantine
	case string(types.DecisionMonitorOnly):
		return types.DecisionMonitorOnly
	default:
		return types.DecisionAllow
	}
}

func decodeRuleAction(raw json.RawMessage, actionText string) (rules.RuleAction, error) {
	var action rules.RuleAction
	trimmed := strings.TrimSpace(string(raw))
	switch {
	case trimmed == "", trimmed == "null":
		// fall through to actionText
	case strings.HasPrefix(trimmed, "\""):
		var legacy string
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return rules.RuleAction{}, fmt.Errorf("invalid action")
		}
		action.Decision = policyDecision(legacy)
	default:
		if err := json.Unmarshal(raw, &action); err != nil {
			return rules.RuleAction{}, fmt.Errorf("invalid action")
		}
	}
	if action.Decision == "" && actionText != "" {
		action.Decision = policyDecision(actionText)
	}
	return action, nil
}
