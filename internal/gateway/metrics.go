package gateway

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/mcpids/mcpids/internal/telemetry"
	"github.com/mcpids/mcpids/pkg/types"
)

// PipelineMetrics wraps the telemetry Metrics struct and provides
// convenience methods for recording pipeline-level observations.
type PipelineMetrics struct {
	m *telemetry.Metrics
}

// NewPipelineMetrics creates a PipelineMetrics recorder.
// If m is nil, all recording methods are no-ops.
func NewPipelineMetrics(m *telemetry.Metrics) *PipelineMetrics {
	return &PipelineMetrics{m: m}
}

// RecordRequest records that a gateway request was processed.
func (pm *PipelineMetrics) RecordRequest(ctx context.Context, method, direction string, duration time.Duration) {
	if pm == nil || pm.m == nil {
		return
	}

	attrs := metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("direction", direction),
	)

	pm.m.GatewayRequestsTotal.Add(ctx, 1, attrs)
	pm.m.GatewayRequestDuration.Record(ctx, float64(duration.Milliseconds()), attrs)
}

// RecordVerdict records a policy verdict decision.
func (pm *PipelineMetrics) RecordVerdict(ctx context.Context, verdict *types.Verdict) {
	if pm == nil || pm.m == nil || verdict == nil {
		return
	}

	attrs := metric.WithAttributes(
		attribute.String("decision", string(verdict.Decision)),
		attribute.String("severity", string(verdict.Severity)),
	)

	pm.m.VerdictDecisions.Add(ctx, 1, attrs)

	switch verdict.Decision {
	case types.DecisionDeny, types.DecisionQuarantine:
		pm.m.ToolCallsBlocked.Add(ctx, 1)
	case types.DecisionRedact:
		pm.m.ToolCallsRedacted.Add(ctx, 1)
	case types.DecisionHide:
		pm.m.ToolsHiddenTotal.Add(ctx, 1)
	}
}

// RecordToolCall records that a tool call was intercepted.
func (pm *PipelineMetrics) RecordToolCall(ctx context.Context, toolName string) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.ToolCallsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool", toolName),
	))
}

// RecordApprovalCreated records that a new approval request was created.
func (pm *PipelineMetrics) RecordApprovalCreated(ctx context.Context) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.ApprovalsCreated.Add(ctx, 1)
	pm.m.ApprovalsPending.Add(ctx, 1)
}

// RecordApprovalResolved records that an approval was decided (approved or denied).
func (pm *PipelineMetrics) RecordApprovalResolved(ctx context.Context) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.ApprovalsPending.Add(ctx, -1)
}

// RecordSessionCreated records a new active session.
func (pm *PipelineMetrics) RecordSessionCreated(ctx context.Context) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.SessionsActive.Add(ctx, 1)
}

// RecordSessionClosed records a session closing.
func (pm *PipelineMetrics) RecordSessionClosed(ctx context.Context) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.SessionsActive.Add(ctx, -1)
}

// RecordSessionQuarantined records a session quarantine.
func (pm *PipelineMetrics) RecordSessionQuarantined(ctx context.Context) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.SessionsQuarantined.Add(ctx, 1)
	pm.m.SessionsActive.Add(ctx, -1) // no longer "active"
}

// RecordPolicyEvalDuration records how long a policy evaluation took.
func (pm *PipelineMetrics) RecordPolicyEvalDuration(ctx context.Context, duration time.Duration) {
	if pm == nil || pm.m == nil {
		return
	}
	pm.m.PolicyEvalDuration.Record(ctx, float64(duration.Milliseconds()))
}
