package gateway

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/mcpids/mcpids/internal/mcp"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
)

// contextKey is a private type for context keys in the gateway package.
type contextKey int

const (
	contextKeySession   contextKey = iota // *mcp.Session
	contextKeyServerID                    // string
	contextKeyProxyMeta                   // *proxyMeta (used internally by proxy)
)

// SessionFromContext returns the *mcp.Session stored in the context, or nil.
func SessionFromContext(ctx context.Context) *mcp.Session {
	sess, _ := ctx.Value(contextKeySession).(*mcp.Session)
	return sess
}

// ServerIDFromContext returns the server ID stored in the context, or "".
func ServerIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(contextKeyServerID).(string)
	return id
}

// SessionMiddleware resolves the MCP session from the MCP-Session-Id HTTP header.
// If the header is absent or the session is unknown, a new session is created.
// The resolved session is injected into the request context.
func SessionMiddleware(sessions sessionpkg.Manager, tenantID, agentID, serverID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			externalID := r.Header.Get("Mcp-Session-Id")

			var sess *mcp.Session
			if externalID != "" {
				s, err := sessions.GetByExternalID(ctx, externalID)
				if err == nil && s != nil {
					sess = s
				}
			}

			if sess == nil {
				sess = &mcp.Session{
					ExternalID: externalID,
					TenantID:   tenantID,
					AgentID:    agentID,
					ServerID:   serverID,
					Transport:  "http",
					State:      mcp.StateNew,
				}
				if err := sessions.Create(ctx, sess); err != nil {
					slog.Warn("middleware: session create failed", "error", err)
					if sess.ID == "" {
						sess.ID = uuid.New().String()
					}
				}
			}

			_ = sessions.Touch(ctx, sess.ID)

			ctx = context.WithValue(ctx, contextKeySession, sess)
			ctx = context.WithValue(ctx, contextKeyServerID, serverID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RecoveryMiddleware catches panics and returns 500.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("gateway: panic in handler", "panic", rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture the status code.
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *loggingResponseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogMiddleware logs each HTTP request with method, path, status, and duration.
func RequestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		slog.Info("gateway: request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", lrw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}
