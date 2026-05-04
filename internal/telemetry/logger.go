// Package telemetry initializes OpenTelemetry SDK and provides structured logging helpers.
package telemetry

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel/trace"
)

// traceHandler is an slog.Handler that injects trace_id and span_id into every log record.
type traceHandler struct {
	inner slog.Handler
}

// NewTraceHandler wraps an existing slog.Handler and adds OTel trace context to records.
func NewTraceHandler(inner slog.Handler) slog.Handler {
	return &traceHandler{inner: inner}
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	if spanCtx.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{inner: h.inner.WithGroup(name)}
}

// InitLogger configures the default slog logger based on level and format settings.
// Call this once at startup before any logging occurs.
func InitLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var base slog.Handler
	if format == "text" {
		base = slog.NewTextHandler(os.Stdout, opts)
	} else {
		base = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(NewTraceHandler(base))
	slog.SetDefault(logger)
	return logger
}

// L returns the default slog logger.
func L() *slog.Logger {
	return slog.Default()
}

// With returns a logger with additional attributes pre-attached.
// Useful for request-scoped logging with tenant_id, session_id, etc.
func With(args ...any) *slog.Logger {
	return slog.Default().With(args...)
}
