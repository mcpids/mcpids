package sensor

import (
	"context"
	"log/slog"
)

// StubManager is a no-op sensor implementation used on platforms that do not
// support eBPF (macOS, Windows) or when eBPF is explicitly disabled.
// It satisfies the Manager interface and never returns events.
type StubManager struct {
	events chan Event
}

// NewStubManager creates a stub sensor manager.
func NewStubManager() Manager {
	return &StubManager{
		events: make(chan Event),
	}
}

// Start implements Manager. Logs a debug message and returns immediately.
func (s *StubManager) Start(ctx context.Context) error {
	slog.Debug("sensor: stub manager started (no eBPF events will be generated)")
	return nil
}

// Stop implements Manager. Closes the event channel.
func (s *StubManager) Stop() error {
	close(s.events)
	return nil
}

// Events implements Manager. Returns a channel that never receives events.
func (s *StubManager) Events() <-chan Event {
	return s.events
}

// IsSupported implements Manager. Always returns false for the stub.
func (s *StubManager) IsSupported() bool {
	return false
}
