package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all metric instruments for MCPIDS.
// Instruments are registered once at startup and shared globally.
type Metrics struct {
	// Gateway metrics
	GatewayRequestsTotal   metric.Int64Counter
	GatewayRequestDuration metric.Float64Histogram
	VerdictDecisions       metric.Int64Counter
	ToolCallsTotal         metric.Int64Counter
	ToolCallsBlocked       metric.Int64Counter
	ToolCallsRedacted      metric.Int64Counter
	ToolsHiddenTotal       metric.Int64Counter
	ApprovalsCreated       metric.Int64Counter
	ApprovalsPending       metric.Int64UpDownCounter
	SessionsActive         metric.Int64UpDownCounter
	SessionsQuarantined    metric.Int64Counter

	// Control plane metrics
	IncidentsCreated   metric.Int64Counter
	DetectionsTotal    metric.Int64Counter
	RulesLoaded        metric.Int64ObservableGauge
	PolicyEvalDuration metric.Float64Histogram
}

// RegisterMetrics creates and registers all metric instruments.
// Returns a Metrics struct for use by the caller.
func RegisterMetrics(meterName string) (*Metrics, error) {
	meter := otel.GetMeterProvider().Meter(meterName)

	m := &Metrics{}
	var err error

	if m.GatewayRequestsTotal, err = meter.Int64Counter(
		"mcpids.gateway.requests.total",
		metric.WithDescription("Total MCP requests processed by the gateway"),
	); err != nil {
		return nil, err
	}

	if m.GatewayRequestDuration, err = meter.Float64Histogram(
		"mcpids.gateway.request.duration_ms",
		metric.WithDescription("Gateway request processing duration in milliseconds"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	if m.VerdictDecisions, err = meter.Int64Counter(
		"mcpids.policy.verdict.decisions.total",
		metric.WithDescription("Policy verdict decisions by decision type and severity"),
	); err != nil {
		return nil, err
	}

	if m.ToolCallsTotal, err = meter.Int64Counter(
		"mcpids.tools.calls.total",
		metric.WithDescription("Total tool calls intercepted"),
	); err != nil {
		return nil, err
	}

	if m.ToolCallsBlocked, err = meter.Int64Counter(
		"mcpids.tools.calls.blocked.total",
		metric.WithDescription("Tool calls blocked by policy"),
	); err != nil {
		return nil, err
	}

	if m.ToolCallsRedacted, err = meter.Int64Counter(
		"mcpids.tools.calls.redacted.total",
		metric.WithDescription("Tool responses with content redacted"),
	); err != nil {
		return nil, err
	}

	if m.ToolsHiddenTotal, err = meter.Int64Counter(
		"mcpids.tools.hidden.total",
		metric.WithDescription("Tools hidden from tools/list responses"),
	); err != nil {
		return nil, err
	}

	if m.ApprovalsCreated, err = meter.Int64Counter(
		"mcpids.approvals.created.total",
		metric.WithDescription("Total HITL approval requests created"),
	); err != nil {
		return nil, err
	}

	if m.ApprovalsPending, err = meter.Int64UpDownCounter(
		"mcpids.approvals.pending",
		metric.WithDescription("Current number of pending approval requests"),
	); err != nil {
		return nil, err
	}

	if m.SessionsActive, err = meter.Int64UpDownCounter(
		"mcpids.sessions.active",
		metric.WithDescription("Number of currently active MCP sessions"),
	); err != nil {
		return nil, err
	}

	if m.SessionsQuarantined, err = meter.Int64Counter(
		"mcpids.sessions.quarantined.total",
		metric.WithDescription("Total sessions quarantined by policy"),
	); err != nil {
		return nil, err
	}

	if m.IncidentsCreated, err = meter.Int64Counter(
		"mcpids.incidents.created.total",
		metric.WithDescription("Total incidents created"),
	); err != nil {
		return nil, err
	}

	if m.DetectionsTotal, err = meter.Int64Counter(
		"mcpids.detections.total",
		metric.WithDescription("Total detections recorded"),
	); err != nil {
		return nil, err
	}

	if m.PolicyEvalDuration, err = meter.Float64Histogram(
		"mcpids.policy.eval.duration_ms",
		metric.WithDescription("Policy engine evaluation duration in milliseconds"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	return m, nil
}
