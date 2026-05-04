package agent

import (
	"context"
	"log/slog"
	"time"
)

// Heartbeat periodically polls the control plane for policy updates
// and reports the agent's liveness.
type Heartbeat struct {
	interval time.Duration
	// onTick is called on each heartbeat cycle. It should poll for policy updates.
	onTick func(ctx context.Context) error
}

// NewHeartbeat creates a Heartbeat that calls onTick at the given interval.
func NewHeartbeat(interval time.Duration, onTick func(ctx context.Context) error) *Heartbeat {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Heartbeat{interval: interval, onTick: onTick}
}

// Run starts the heartbeat loop. It blocks until ctx is cancelled.
func (h *Heartbeat) Run(ctx context.Context) error {
	// Fire immediately on startup.
	if err := h.tick(ctx); err != nil {
		slog.Warn("agent: heartbeat: initial tick failed", "error", err)
	}

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := h.tick(ctx); err != nil {
				slog.Warn("agent: heartbeat: tick failed", "error", err)
				// Non-fatal: keep running, use last known policy.
			}
		}
	}
}

func (h *Heartbeat) tick(ctx context.Context) error {
	slog.Debug("agent: heartbeat: tick")
	return h.onTick(ctx)
}
