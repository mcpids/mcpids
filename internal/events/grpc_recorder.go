package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"github.com/mcpids/mcpids/pkg/types"
	"google.golang.org/grpc"
)

// GRPCRecorder publishes events to the control-plane EventService.
type GRPCRecorder struct {
	client mcpidsv1.EventServiceClient
}

// NewGRPCRecorder creates a service-plane event recorder.
func NewGRPCRecorder(conn grpc.ClientConnInterface) *GRPCRecorder {
	return &GRPCRecorder{client: mcpidsv1.NewEventServiceClient(conn)}
}

// RecordCall implements Recorder.
func (r *GRPCRecorder) RecordCall(ctx context.Context, rec CallRecord) (string, error) {
	if r == nil || r.client == nil {
		return rec.ID, nil
	}
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	payload := rec.RequestPayload
	if len(payload) == 0 {
		payload = rec.ResponsePayload
	}
	_, err := r.client.PublishEvent(ctx, &mcpidsv1.Event{
		EventId:     rec.ID,
		Kind:        callEventKind(rec.Method, rec.Verdict),
		TenantId:    rec.TenantID,
		AgentId:     rec.AgentID,
		SessionId:   rec.SessionID,
		ServerId:    rec.ServerID,
		Timestamp:   timestampMillis(rec.CalledAt),
		PayloadJson: payload,
		Verdict:     toRPCVerdict(rec.Verdict),
	})
	if err != nil {
		return "", err
	}
	return rec.ID, nil
}

// RecordDetection implements Recorder.
func (r *GRPCRecorder) RecordDetection(ctx context.Context, rec DetectionRecord) (string, error) {
	if r == nil || r.client == nil {
		return rec.CallID, nil
	}
	eventID := rec.CallID
	if eventID == "" {
		eventID = uuid.New().String()
	}
	payload, err := json.Marshal(map[string]any{
		"call_id":  rec.CallID,
		"evidence": rec.Evidence,
	})
	if err != nil {
		return "", err
	}
	_, err = r.client.PublishEvent(ctx, &mcpidsv1.Event{
		EventId:     eventID,
		Kind:        mcpidsv1.EventKind_EVENT_KIND_DETECTION,
		TenantId:    rec.TenantID,
		SessionId:   rec.SessionID,
		ServerId:    rec.ServerID,
		Timestamp:   timestampMillis(rec.CreatedAt),
		PayloadJson: payload,
		Verdict:     toRPCVerdict(rec.Verdict),
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
}

// RecordAudit implements Recorder.
func (r *GRPCRecorder) RecordAudit(ctx context.Context, rec AuditRecord) error {
	if r == nil || r.client == nil {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"action":        rec.Action,
		"resource_kind": rec.ResourceKind,
		"resource_id":   rec.ResourceID,
		"actor_kind":    rec.ActorKind,
		"ip_address":    rec.IPAddress,
		"payload":       rec.Payload,
	})
	if err != nil {
		return err
	}
	eventKind := mcpidsv1.EventKind_EVENT_KIND_AUDIT
	if rec.Action == "sensor.event" {
		eventKind = mcpidsv1.EventKind_EVENT_KIND_SENSOR
	}
	_, err = r.client.PublishEvent(ctx, &mcpidsv1.Event{
		EventId:     uuid.New().String(),
		Kind:        eventKind,
		TenantId:    rec.TenantID,
		AgentId:     rec.ActorID,
		Timestamp:   time.Now().UTC().UnixMilli(),
		PayloadJson: payload,
	})
	return err
}

func callEventKind(method string, verdict *types.Verdict) mcpidsv1.EventKind {
	if method == "tools/list" {
		if verdict != nil && verdict.Decision == types.DecisionHide {
			return mcpidsv1.EventKind_EVENT_KIND_TOOLS_FILTERED
		}
		return mcpidsv1.EventKind_EVENT_KIND_TOOLS_LIST
	}
	if verdict != nil && verdict.IsBlocking() {
		return mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL_BLOCKED
	}
	return mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL
}

func toRPCVerdict(v *types.Verdict) *mcpidsv1.Verdict {
	if v == nil {
		return nil
	}
	out := &mcpidsv1.Verdict{
		Decision:          toRPCDecision(v.Decision),
		Severity:          toRPCSeverity(v.Severity),
		Reasons:           v.Reasons,
		MatchedRules:      v.MatchedRules,
		SemanticLabels:    v.SemanticLabels,
		Confidence:        v.Confidence,
		RequiresApproval:  v.RequiresApproval,
		IncidentCandidate: v.IncidentCandidate,
		EvidenceRefs:      v.EvidenceRefs,
		RiskScore:         v.RiskScore,
	}
	for _, redaction := range v.Redactions {
		out.Redactions = append(out.Redactions, &mcpidsv1.Redaction{
			FieldPath:   redaction.FieldPath,
			Pattern:     redaction.Pattern,
			Replacement: redaction.Replacement,
		})
	}
	return out
}

func toRPCDecision(decision types.Decision) mcpidsv1.Decision {
	switch decision {
	case types.DecisionAllow:
		return mcpidsv1.Decision_DECISION_ALLOW
	case types.DecisionDeny:
		return mcpidsv1.Decision_DECISION_DENY
	case types.DecisionHide:
		return mcpidsv1.Decision_DECISION_HIDE
	case types.DecisionRedact:
		return mcpidsv1.Decision_DECISION_REDACT
	case types.DecisionQuarantine:
		return mcpidsv1.Decision_DECISION_QUARANTINE
	case types.DecisionRequireApproval:
		return mcpidsv1.Decision_DECISION_REQUIRE_APPROVAL
	case types.DecisionMonitorOnly:
		return mcpidsv1.Decision_DECISION_MONITOR_ONLY
	default:
		return mcpidsv1.Decision_DECISION_UNSPECIFIED
	}
}

func toRPCSeverity(severity types.Severity) mcpidsv1.Severity {
	switch severity {
	case types.SeverityInfo:
		return mcpidsv1.Severity_SEVERITY_INFO
	case types.SeverityLow:
		return mcpidsv1.Severity_SEVERITY_LOW
	case types.SeverityMedium:
		return mcpidsv1.Severity_SEVERITY_MEDIUM
	case types.SeverityHigh:
		return mcpidsv1.Severity_SEVERITY_HIGH
	case types.SeverityCritical:
		return mcpidsv1.Severity_SEVERITY_CRITICAL
	default:
		return mcpidsv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func timestampMillis(ts time.Time) int64 {
	if ts.IsZero() {
		return time.Now().UTC().UnixMilli()
	}
	return ts.UnixMilli()
}
