// Command sensor-ebpf is the MCPIDS kernel visibility sensor.
// It uses eBPF to observe process creation and network connections,
// enriching MCP call records with process and connection context.
//
// Requirements:
//   - Linux kernel ≥ 5.8
//   - CAP_BPF capability or root
//   - Compiled eBPF object files in --programs-dir
//
// On unsupported platforms the sensor runs in stub mode (no events emitted).
//
// Usage:
//
//	sensor-ebpf --config sensor.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mcpids/mcpids/internal/config"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/sensor"
	pgstore "github.com/mcpids/mcpids/internal/storage/postgres"
	"github.com/mcpids/mcpids/internal/telemetry"
	"github.com/mcpids/mcpids/internal/transport"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		slog.Error("sensor: fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfgFile := flag.String("config", "", "path to sensor YAML config file")
	flag.Parse()

	// ── Config ──────────────────────────────────────────────────────────────────
	cfg, err := config.LoadSensorConfig(*cfgFile)
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
		slog.Warn("sensor: telemetry init failed (continuing)", "error", err)
	} else {
		defer tel.Shutdown(ctx)
	}
	if _, err := telemetry.RegisterMetrics("mcpids/sensor"); err != nil {
		slog.Warn("sensor: metrics registration failed (continuing)", "error", err)
	}

	// ── Control-plane gRPC + PostgreSQL fallback ───────────────────────────────
	var recorder eventspkg.Recorder
	if cfg.ControlPlane.Address != "" {
		if cpConn, err := transport.DialControlPlane(ctx, cfg.ControlPlane); err != nil {
			slog.Warn("sensor: control-plane gRPC unavailable, falling back to direct database", "error", err)
		} else {
			defer cpConn.Close()
			recorder = eventspkg.NewGRPCRecorder(cpConn)
			slog.Info("sensor: connected to control-plane gRPC", "addr", cfg.ControlPlane.Address)
		}
	}
	if cfg.Database.URL != "" {
		db, err := pgstore.NewDB(ctx, pgstore.Config{
			URL:             cfg.Database.URL,
			MaxConns:        cfg.Database.MaxConns,
			MinConns:        cfg.Database.MinConns,
			MaxConnLifetime: cfg.Database.MaxConnLifetime,
			MaxConnIdleTime: cfg.Database.MaxConnIdleTime,
		})
		if err != nil {
			slog.Warn("sensor: postgres unavailable, using log-only event sink", "error", err)
		} else {
			defer db.Close()
			if recorder == nil {
				recorder = eventspkg.NewPGRecorder(db.Pool())
			}
		}
	}

	// ── Sensor manager ───────────────────────────────────────────────────────────
	sensorCfg := sensor.Config{
		Enabled:         cfg.EBPF.Enabled,
		ProgramsDir:     cfg.EBPF.ProgramsDir,
		AttachKprobes:   cfg.EBPF.AttachKprobes,
		AttachUprobes:   cfg.EBPF.AttachUprobes,
		EventBufferSize: cfg.EBPF.EventBufferSize,
		TenantID:        cfg.TenantID,
		AgentID:         cfg.AgentID,
	}

	mgr := sensor.NewManager(sensorCfg)

	// ── Signal handling ─────────────────────────────────────────────────────────
	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Start sensor ────────────────────────────────────────────────────────────
	if !mgr.IsSupported() {
		slog.Warn("sensor: eBPF not supported on this platform; running in stub mode")
	}

	if err := mgr.Start(runCtx); err != nil {
		return fmt.Errorf("sensor: start: %w", err)
	}
	defer func() { _ = mgr.Stop() }()

	slog.Info("sensor: running",
		"tenant_id", cfg.TenantID,
		"supported", mgr.IsSupported())

	// ── Event loop ───────────────────────────────────────────────────────────────
	sensor.ProcessEventStream(runCtx, mgr.Events(), func(ev sensor.Event) {
		slog.Info("sensor: event",
			"kind", ev.Kind,
			"pid", ev.PID,
			"comm", ev.Comm,
			"exe", ev.ExePath)
		if recorder != nil {
			if err := recorder.RecordAudit(runCtx, eventspkg.AuditRecord{
				TenantID:     cfg.TenantID,
				ActorID:      cfg.AgentID,
				ActorKind:    "agent",
				Action:       "sensor.event",
				ResourceKind: "sensor",
				Payload: map[string]any{
					"kind":      ev.Kind,
					"pid":       ev.PID,
					"ppid":      ev.PPID,
					"comm":      ev.Comm,
					"exe":       ev.ExePath,
					"args":      ev.Args,
					"source_ip": ev.SrcAddr.String(),
					"source_port": ev.SrcPort,
					"dest_ip":   ev.DstAddr.String(),
					"dest_port": ev.DstPort,
					"bytes":     len(ev.Payload),
					"timestamp": ev.Timestamp,
				},
			}); err != nil {
				slog.Warn("sensor: audit persist failed", "kind", ev.Kind, "error", err)
			}
		}
	})

	return nil
}
