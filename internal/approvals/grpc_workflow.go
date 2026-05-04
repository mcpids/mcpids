package approvals

import (
	"context"
	"time"

	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"github.com/mcpids/mcpids/pkg/types"
)

// grpcWorkflow delegates approval lifecycle calls to the control-plane ApprovalService.
type grpcWorkflow struct {
	client   mcpidsv1.ApprovalServiceClient
	tenantID string
	timeout  time.Duration
}

// NewGRPCWorkflow creates a service-plane-backed approval workflow.
func NewGRPCWorkflow(client mcpidsv1.ApprovalServiceClient, tenantID string, defaultTimeout time.Duration) Workflow {
	if defaultTimeout <= 0 {
		defaultTimeout = 5 * time.Minute
	}
	return &grpcWorkflow{
		client:   client,
		tenantID: tenantID,
		timeout:  defaultTimeout,
	}
}

// Submit implements Workflow.
func (w *grpcWorkflow) Submit(ctx context.Context, req *Request) (string, error) {
	if w == nil || w.client == nil || req == nil {
		return "", nil
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = w.tenantID
	}
	resp, err := w.client.SubmitApproval(ctx, &mcpidsv1.SubmitApprovalRequest{
		TenantId:       tenantID,
		AgentId:        req.AgentID,
		SessionId:      req.SessionID,
		ServerId:       req.ServerID,
		ToolName:       req.ToolName,
		RawPayload:     req.RawPayload,
		Verdict:        verdictToRPC(&req.Verdict),
		TimeoutSeconds: int32(w.timeout.Seconds()),
	})
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", nil
	}
	req.ID = resp.RequestId
	req.Status = StatusPending
	req.CreatedAt = time.Now().UTC()
	req.ExpiresAt = time.UnixMilli(resp.ExpiresAt).UTC()
	return resp.RequestId, nil
}

// WaitForDecision implements Workflow.
func (w *grpcWorkflow) WaitForDecision(ctx context.Context, requestID string) (*Decision, error) {
	if w == nil || w.client == nil {
		return nil, types.ErrApprovalTimeout
	}
	stream, err := w.client.WatchDecision(ctx, &mcpidsv1.WatchDecisionRequest{
		RequestId: requestID,
		TenantId:  w.tenantID,
	})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	decision := &Decision{
		RequestID: resp.RequestId,
		Status:    approvalStatusFromRPC(resp.Status),
		DecidedBy: resp.DecidedBy,
		Notes:     resp.Notes,
		Timestamp: time.UnixMilli(resp.DecidedAt).UTC(),
	}
	switch decision.Status {
	case StatusDenied:
		return decision, types.ErrApprovalDenied
	case StatusExpired:
		return decision, types.ErrApprovalTimeout
	default:
		return decision, nil
	}
}

// Decide implements Workflow.
func (w *grpcWorkflow) Decide(ctx context.Context, dec *Decision) error {
	if w == nil || w.client == nil || dec == nil {
		return nil
	}
	_, err := w.client.Decide(ctx, &mcpidsv1.DecideRequest{
		RequestId:      dec.RequestID,
		TenantId:       w.tenantID,
		ApproverUserId: dec.DecidedBy,
		Decision:       approvalStatusToRPC(dec.Status),
		Notes:          dec.Notes,
	})
	return err
}

// Get is not exposed by ApprovalService; gateway-side callers do not need it.
func (w *grpcWorkflow) Get(context.Context, string) (*Request, error) {
	return nil, nil
}

// ListPending implements Workflow.
func (w *grpcWorkflow) ListPending(ctx context.Context, tenantID string, limit, offset int) ([]*Request, error) {
	if w == nil || w.client == nil {
		return nil, nil
	}
	if tenantID == "" {
		tenantID = w.tenantID
	}
	resp, err := w.client.ListPending(ctx, &mcpidsv1.ListPendingRequest{
		TenantId: tenantID,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	out := make([]*Request, 0, len(resp.Items))
	for _, item := range resp.Items {
		if item == nil {
			continue
		}
		out = append(out, &Request{
			ID:        item.RequestId,
			TenantID:  item.TenantId,
			SessionID: item.SessionId,
			ServerID:  item.ServerId,
			ToolName:  item.ToolName,
			Verdict:   verdictFromRPC(item.Verdict),
			Status:    approvalStatusFromRPC(item.Status),
			CreatedAt: time.UnixMilli(item.CreatedAt).UTC(),
			ExpiresAt: time.UnixMilli(item.ExpiresAt).UTC(),
		})
	}
	return out, nil
}

func verdictToRPC(v *types.Verdict) *mcpidsv1.Verdict {
	if v == nil {
		return nil
	}
	out := &mcpidsv1.Verdict{
		Decision:          decisionToRPC(v.Decision),
		Severity:          severityToRPC(v.Severity),
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

func verdictFromRPC(v *mcpidsv1.Verdict) types.Verdict {
	if v == nil {
		return types.Verdict{Decision: types.DecisionAllow, Severity: types.SeverityInfo}
	}
	out := types.Verdict{
		Decision:          decisionFromRPC(v.Decision),
		Severity:          severityFromRPC(v.Severity),
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
		if redaction == nil {
			continue
		}
		out.Redactions = append(out.Redactions, types.Redaction{
			FieldPath:   redaction.FieldPath,
			Pattern:     redaction.Pattern,
			Replacement: redaction.Replacement,
		})
	}
	return out
}

func decisionToRPC(decision types.Decision) mcpidsv1.Decision {
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

func decisionFromRPC(decision mcpidsv1.Decision) types.Decision {
	switch decision {
	case mcpidsv1.Decision_DECISION_ALLOW:
		return types.DecisionAllow
	case mcpidsv1.Decision_DECISION_DENY:
		return types.DecisionDeny
	case mcpidsv1.Decision_DECISION_HIDE:
		return types.DecisionHide
	case mcpidsv1.Decision_DECISION_REDACT:
		return types.DecisionRedact
	case mcpidsv1.Decision_DECISION_QUARANTINE:
		return types.DecisionQuarantine
	case mcpidsv1.Decision_DECISION_REQUIRE_APPROVAL:
		return types.DecisionRequireApproval
	case mcpidsv1.Decision_DECISION_MONITOR_ONLY:
		return types.DecisionMonitorOnly
	default:
		return types.DecisionAllow
	}
}

func severityToRPC(severity types.Severity) mcpidsv1.Severity {
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

func severityFromRPC(severity mcpidsv1.Severity) types.Severity {
	switch severity {
	case mcpidsv1.Severity_SEVERITY_INFO:
		return types.SeverityInfo
	case mcpidsv1.Severity_SEVERITY_LOW:
		return types.SeverityLow
	case mcpidsv1.Severity_SEVERITY_MEDIUM:
		return types.SeverityMedium
	case mcpidsv1.Severity_SEVERITY_HIGH:
		return types.SeverityHigh
	case mcpidsv1.Severity_SEVERITY_CRITICAL:
		return types.SeverityCritical
	default:
		return types.SeverityInfo
	}
}

func approvalStatusToRPC(statusValue Status) mcpidsv1.ApprovalStatus {
	switch statusValue {
	case StatusPending:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_PENDING
	case StatusApproved:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	case StatusDenied:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_DENIED
	case StatusExpired:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_EXPIRED
	default:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_UNSPECIFIED
	}
}

func approvalStatusFromRPC(statusValue mcpidsv1.ApprovalStatus) Status {
	switch statusValue {
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_APPROVED:
		return StatusApproved
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_DENIED:
		return StatusDenied
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_EXPIRED:
		return StatusExpired
	default:
		return StatusPending
	}
}
