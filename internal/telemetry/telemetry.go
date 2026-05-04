package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Provider holds initialized OTel SDK providers.
// Call Shutdown on program exit to flush pending telemetry.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *metric.MeterProvider
	metricsServer  *http.Server
}

// Config is the telemetry initialization configuration.
type Config struct {
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string // gRPC endpoint; empty = disable trace export
	PrometheusAddr string // address for /metrics; empty = disable
	LogLevel       string
	LogFormat      string
}

// Init initializes the OpenTelemetry SDK (traces + metrics) and the slog logger.
// Returns a Provider whose Shutdown method must be deferred.
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: create resource: %w", err)
	}

	// ─── Traces ─────────────────────────────────────────────────────────────────
	var tp *sdktrace.TracerProvider
	if cfg.OTLPEndpoint != "" {
		exp, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
			otlptracegrpc.WithInsecure(), // TLS should be enabled in production
		)
		if err != nil {
			return nil, fmt.Errorf("telemetry: create OTLP exporter: %w", err)
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
	} else {
		// No-op tracer for dev without a collector.
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.NeverSample()),
		)
	}

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// ─── Metrics ─────────────────────────────────────────────────────────────────
	promExp, err := promexporter.New()
	if err != nil {
		return nil, fmt.Errorf("telemetry: create Prometheus exporter: %w", err)
	}
	mp := metric.NewMeterProvider(
		metric.WithReader(promExp),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	var metricsServer *http.Server
	if cfg.PrometheusAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		metricsServer = &http.Server{
			Addr:              cfg.PrometheusAddr,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Warn("telemetry: metrics server failed", "addr", cfg.PrometheusAddr, "error", err)
			}
		}()
	}

	// ─── Logging ─────────────────────────────────────────────────────────────────
	InitLogger(cfg.LogLevel, cfg.LogFormat)

	return &Provider{
		tracerProvider: tp,
		meterProvider:  mp,
		metricsServer:  metricsServer,
	}, nil
}

// Shutdown flushes and closes all telemetry providers.
// Call this in a deferred block at the top of main().
func (p *Provider) Shutdown(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if p.tracerProvider != nil {
		_ = p.tracerProvider.Shutdown(shutdownCtx)
	}
	if p.meterProvider != nil {
		_ = p.meterProvider.Shutdown(shutdownCtx)
	}
	if p.metricsServer != nil {
		_ = p.metricsServer.Shutdown(shutdownCtx)
	}
}
