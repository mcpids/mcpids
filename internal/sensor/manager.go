package sensor

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

// NewManager returns the appropriate Manager for the current platform.
// On Linux with eBPF support it returns an eBPF-backed manager (when enabled).
// On all other platforms it returns a StubManager.
// The config parameter controls which attach points are activated.
func NewManager(cfg Config) Manager {
	if !cfg.Enabled {
		slog.Info("sensor: eBPF disabled by config, using stub")
		return NewStubManager()
	}

	if runtime.GOOS != "linux" {
		slog.Info("sensor: eBPF not supported on this platform, using stub",
			"os", runtime.GOOS)
		return NewStubManager()
	}

	// On Linux, attempt to load the real eBPF manager.
	// The ebpfManager type is defined in ebpf_linux.go (build-tagged).
	m, err := newEBPFManager(cfg)
	if err != nil {
		slog.Warn("sensor: eBPF load failed, falling back to stub",
			"error", err)
		return NewStubManager()
	}
	return m
}

// Config controls the sensor startup behavior.
type Config struct {
	// Enabled controls whether eBPF programs are loaded.
	Enabled bool

	// ProgramsDir is the directory containing compiled eBPF object files (.o).
	ProgramsDir string

	// AttachKprobes enables kprobe-based attach points (process exec/exit).
	AttachKprobes bool

	// AttachUprobes enables uprobe-based TLS plaintext hooks.
	AttachUprobes bool

	// TLSLibPath is the path to the shared library to attach TLS uprobes to.
	// Typical values: "/usr/lib/x86_64-linux-gnu/libssl.so.3" or the path
	// returned by `ldconfig -p | grep libssl`.
	// Required when AttachUprobes is true.
	TLSLibPath string

	// EventBufferSize is the capacity of the event channel.
	// Default: 1024
	EventBufferSize int

	// TenantID is injected into every event emitted by this sensor.
	TenantID string

	// AgentID is injected into every event emitted by this sensor.
	AgentID string
}

// DefaultConfig returns safe default sensor configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:         false, // opt-in
		AttachKprobes:   true,
		AttachUprobes:   false, // requires binary-specific offsets
		EventBufferSize: 1024,
	}
}

// ─── Event processing helpers ─────────────────────────────────────────────────

// ProcessEventStream reads events from src and calls handler for each one.
// It stops when ctx is cancelled or src is closed.
// This is a utility for consumers of the sensor.
func ProcessEventStream(ctx context.Context, src <-chan Event, handler func(Event)) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			handler(ev)
		}
	}
}

// FilterNetworkEvents returns a channel that only receives TCP connect/accept events.
// The returned channel is closed when src is closed.
func FilterNetworkEvents(src <-chan Event) <-chan Event {
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		for ev := range src {
			if ev.Kind == EventKindTCPConnect || ev.Kind == EventKindTCPAccept {
				out <- ev
			}
		}
	}()
	return out
}

// FilterProcessEvents returns a channel that only receives process exec/exit events.
func FilterProcessEvents(src <-chan Event) <-chan Event {
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		for ev := range src {
			if ev.Kind == EventKindProcessExec || ev.Kind == EventKindProcessExit {
				out <- ev
			}
		}
	}()
	return out
}

// injectContext adds tenant/agent ID to every event from src.
func injectContext(src <-chan Event, tenantID, agentID string) <-chan Event {
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		for ev := range src {
			ev.TenantID = tenantID
			ev.AgentID = agentID
			if ev.Timestamp.IsZero() {
				ev.Timestamp = time.Now().UTC()
			}
			out <- ev
		}
	}()
	return out
}
