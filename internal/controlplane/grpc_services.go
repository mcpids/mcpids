package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/auth"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/graph"
	mcppkg "github.com/mcpids/mcpids/internal/mcp"
	"github.com/mcpids/mcpids/internal/policy/rules"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"github.com/mcpids/mcpids/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReportInventory upserts MCP servers discovered by an agent.
func (s *Server) ReportInventory(ctx context.Context, req *mcpidsv1.InventoryReport) (*mcpidsv1.InventoryAck, error) {
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition, "database not configured")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if strings.TrimSpace(req.TenantId) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	ack := &mcpidsv1.InventoryAck{ServerIds: map[string]string{}}
	for _, srv := range req.Servers {
		if srv == nil || strings.TrimSpace(srv.Name) == "" {
			continue
		}

		transport := srv.Transport
		if transport == "" {
			transport = "stdio"
		}
		metadata := map[string]any{
			"agent_id": req.AgentId,
			"command":  srv.Command,
		}
		for k, v := range srv.Metadata {
			metadata[k] = v
		}
		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal metadata: %v", err)
		}

		var id string
		err = s.db.Pool().QueryRow(ctx,
			`INSERT INTO mcp_servers (tenant_id, name, url, transport, status, metadata, last_seen_at)
			 VALUES ($1, $2, NULLIF($3, ''), $4, 'active', $5::jsonb, NOW())
			 ON CONFLICT (tenant_id, name) DO UPDATE SET
				 url = EXCLUDED.url,
				 transport = EXCLUDED.transport,
				 metadata = EXCLUDED.metadata,
				 last_seen_at = NOW()
			 RETURNING id::text`,
			req.TenantId, srv.Name, srv.Url, transport, string(metadataJSON),
		).Scan(&id)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "upsert server %q: %v", srv.Name, err)
		}
		ack.ServerIds[srv.Name] = id
		if s.eventRecorder != nil {
			_ = s.eventRecorder.RecordAudit(ctx, eventspkg.AuditRecord{
				TenantID:     req.TenantId,
				ActorID:      req.AgentId,
				ActorKind:    "agent",
				Action:       "inventory.reported",
				ResourceKind: "server",
				ResourceID:   id,
				Payload: map[string]any{
					"name":      srv.Name,
					"transport": transport,
				},
			})
		}
	}
	return ack, nil
}

// SubmitToolSnapshot persists the latest tools/list snapshot for a server.
func (s *Server) SubmitToolSnapshot(ctx context.Context, req *mcpidsv1.ToolSnapshotRequest) (*mcpidsv1.ToolSnapshotAck, error) {
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition, "database not configured")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if req.TenantId == "" || req.ServerId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id and server_id are required")
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256(req.ToolsJson))
	var prevChecksum string
	_ = s.db.Pool().QueryRow(ctx,
		`SELECT checksum
		 FROM tool_snapshots
		 WHERE tenant_id = $1 AND server_id = $2
		 ORDER BY captured_at DESC
		 LIMIT 1`,
		req.TenantId, req.ServerId,
	).Scan(&prevChecksum)

	snapshotID := uuid.New().String()
	capturedAt := time.Now().UTC()
	if req.CapturedAt > 0 {
		capturedAt = time.UnixMilli(req.CapturedAt).UTC()
	}
	_, err = s.db.Pool().Exec(ctx,
		`INSERT INTO tool_snapshots (id, server_id, tenant_id, captured_at, checksum, payload)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		snapshotID, req.ServerId, req.TenantId, capturedAt, checksum, jsonTextOrDefault(req.ToolsJson, "[]"),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "insert snapshot: %v", err)
	}

	var toolRows []types.Tool
	if len(req.ToolsJson) > 0 {
		if err := json.Unmarshal(req.ToolsJson, &toolRows); err == nil {
			for _, tool := range toolRows {
				_, upsertErr := s.db.Pool().Exec(ctx,
					`INSERT INTO tools (server_id, tenant_id, name, description, input_schema, is_destructive, is_read_only)
					 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
					 ON CONFLICT (server_id, name) DO UPDATE SET
						 description = EXCLUDED.description,
						 input_schema = EXCLUDED.input_schema,
						 is_destructive = EXCLUDED.is_destructive,
						 is_read_only = EXCLUDED.is_read_only,
						 updated_at = NOW()`,
					req.ServerId,
					req.TenantId,
					tool.Name,
					tool.Description,
					jsonTextOrDefault(tool.InputSchema, "null"),
					tool.IsDestructive,
					tool.IsReadOnly,
				)
				if upsertErr != nil {
					return nil, status.Errorf(codes.Internal, "upsert tool %q: %v", tool.Name, upsertErr)
				}
			}
		}
	}

	return &mcpidsv1.ToolSnapshotAck{
		SnapshotId:    snapshotID,
		HasChanges:    prevChecksum != "" && prevChecksum != checksum,
		ChangeSummary: snapshotChangeSummary(prevChecksum, checksum),
	}, nil
}

// GetServerTools returns the most recent tool snapshot for a server.
func (s *Server) GetServerTools(ctx context.Context, req *mcpidsv1.GetServerToolsRequest) (*mcpidsv1.GetServerToolsResponse, error) {
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition, "database not configured")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if req.ServerId == "" {
		return nil, status.Error(codes.InvalidArgument, "server_id is required")
	}

	query := `SELECT id::text, captured_at, payload FROM tool_snapshots WHERE server_id = $1`
	args := []any{req.ServerId}
	if req.TenantId != "" {
		query += " AND tenant_id = $2"
		args = append(args, req.TenantId)
	}
	query += " ORDER BY captured_at DESC LIMIT 1"

	var snapshotID string
	var snapshotAt time.Time
	var payload []byte
	err = s.db.Pool().QueryRow(ctx, query, args...).Scan(&snapshotID, &snapshotAt, &payload)
	if err != nil {
		return &mcpidsv1.GetServerToolsResponse{ToolsJson: []byte("[]")}, nil
	}

	return &mcpidsv1.GetServerToolsResponse{
		ToolsJson:  payload,
		SnapshotId: snapshotID,
		SnapshotAt: snapshotAt.UnixMilli(),
	}, nil
}

// GetPolicy returns a full effective policy snapshot for one tenant.
func (s *Server) GetPolicy(ctx context.Context, req *mcpidsv1.GetPolicyRequest) (*mcpidsv1.GetPolicyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	snapshot, _, err := s.buildPolicySnapshot(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	return &mcpidsv1.GetPolicyResponse{Snapshot: snapshot}, nil
}

// StreamPolicyUpdates sends an initial policy snapshot then polls for changes.
func (s *Server) StreamPolicyUpdates(req *mcpidsv1.StreamPolicyUpdatesRequest, stream mcpidsv1.PolicyService_StreamPolicyUpdatesServer) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(stream.Context(), req.TenantId)
	if err != nil {
		return err
	}
	req.TenantId = tenantID
	if req.TenantId == "" {
		return status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	snapshot, hash, err := s.buildPolicySnapshot(stream.Context(), req.TenantId)
	if err != nil {
		return err
	}
	var sequence int64 = 1
	if err := stream.Send(&mcpidsv1.PolicyUpdate{
		TenantId:     req.TenantId,
		FullSnapshot: snapshot,
		Sequence:     sequence,
	}); err != nil {
		return err
	}

	interval := s.cfg.Rules.ReloadInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			nextSnapshot, nextHash, err := s.buildPolicySnapshot(stream.Context(), req.TenantId)
			if err != nil {
				return err
			}
			if nextHash == hash {
				continue
			}
			hash = nextHash
			sequence++
			if err := stream.Send(&mcpidsv1.PolicyUpdate{
				TenantId:     req.TenantId,
				FullSnapshot: nextSnapshot,
				Sequence:     sequence,
			}); err != nil {
				return err
			}
		}
	}
}

// PublishEvent persists one gateway/agent/sensor event.
func (s *Server) PublishEvent(ctx context.Context, req *mcpidsv1.Event) (*mcpidsv1.EventAck, error) {
	if req != nil {
		tenantID, err := rpcTenantID(ctx, req.TenantId)
		if err != nil {
			return nil, err
		}
		req.TenantId = tenantID
	}
	if err := s.recordRPCEvent(ctx, req); err != nil {
		return nil, err
	}
	if req == nil || req.EventId == "" {
		return &mcpidsv1.EventAck{EventId: uuid.New().String()}, nil
	}
	return &mcpidsv1.EventAck{EventId: req.EventId}, nil
}

// PublishBatch persists a batch of events.
func (s *Server) PublishBatch(ctx context.Context, req *mcpidsv1.EventBatch) (*mcpidsv1.BatchAck, error) {
	if req == nil {
		return &mcpidsv1.BatchAck{}, nil
	}
	var accepted, rejected int32
	for _, ev := range req.Events {
		if ev != nil {
			tenantID, err := rpcTenantID(ctx, ev.TenantId)
			if err != nil {
				rejected++
				continue
			}
			ev.TenantId = tenantID
		}
		if err := s.recordRPCEvent(ctx, ev); err != nil {
			rejected++
			continue
		}
		accepted++
	}
	return &mcpidsv1.BatchAck{Accepted: accepted, Rejected: rejected}, nil
}

// SubmitApproval creates a pending HITL request.
func (s *Server) SubmitApproval(ctx context.Context, req *mcpidsv1.SubmitApprovalRequest) (*mcpidsv1.SubmitApprovalResponse, error) {
	if s.approvalWF == nil {
		return nil, status.Error(codes.FailedPrecondition, "approval workflow not configured")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	approvalReq := &approvals.Request{
		TenantID:   req.TenantId,
		AgentID:    req.AgentId,
		SessionID:  req.SessionId,
		ServerID:   req.ServerId,
		ToolName:   req.ToolName,
		RawPayload: req.RawPayload,
		Verdict:    fromRPCVerdict(req.Verdict),
	}
	if req.TimeoutSeconds > 0 {
		approvalReq.ExpiresAt = time.Now().UTC().Add(time.Duration(req.TimeoutSeconds) * time.Second)
	}

	requestID, err := s.approvalWF.Submit(ctx, approvalReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "submit approval: %v", err)
	}
	return &mcpidsv1.SubmitApprovalResponse{
		RequestId: requestID,
		ExpiresAt: approvalReq.ExpiresAt.UnixMilli(),
	}, nil
}

// WatchDecision blocks until one approval request is decided.
func (s *Server) WatchDecision(req *mcpidsv1.WatchDecisionRequest, stream mcpidsv1.ApprovalService_WatchDecisionServer) error {
	if s.approvalWF == nil {
		return status.Error(codes.FailedPrecondition, "approval workflow not configured")
	}
	if req == nil || req.RequestId == "" {
		return status.Error(codes.InvalidArgument, "request_id is required")
	}
	tenantID, err := rpcTenantID(stream.Context(), req.TenantId)
	if err != nil {
		return err
	}
	if tenantID != "" {
		existingReq, err := s.approvalWF.Get(stream.Context(), req.RequestId)
		if err != nil {
			return status.Errorf(codes.Internal, "load approval: %v", err)
		}
		if existingReq != nil && existingReq.TenantID != tenantID {
			return status.Error(codes.PermissionDenied, "tenant scope mismatch")
		}
	}

	decision, err := s.approvalWF.WaitForDecision(stream.Context(), req.RequestId)
	if err != nil && err != types.ErrApprovalDenied && err != types.ErrApprovalTimeout {
		return status.Errorf(codes.Internal, "wait for decision: %v", err)
	}
	if decision == nil {
		decision = &approvals.Decision{RequestID: req.RequestId, Status: approvals.StatusExpired, Timestamp: time.Now().UTC()}
	}

	return stream.Send(&mcpidsv1.ApprovalDecision{
		RequestId: decision.RequestID,
		Status:    toRPCApprovalStatus(decision.Status),
		DecidedBy: decision.DecidedBy,
		Notes:     decision.Notes,
		DecidedAt: decision.Timestamp.UnixMilli(),
	})
}

// Decide records a human approval decision.
func (s *Server) Decide(ctx context.Context, req *mcpidsv1.DecideRequest) (*mcpidsv1.DecideResponse, error) {
	if s.approvalWF == nil {
		return nil, status.Error(codes.FailedPrecondition, "approval workflow not configured")
	}
	if req == nil || req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	if tenantID != "" {
		existingReq, err := s.approvalWF.Get(ctx, req.RequestId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "load approval: %v", err)
		}
		if existingReq != nil && existingReq.TenantID != tenantID {
			return nil, status.Error(codes.PermissionDenied, "tenant scope mismatch")
		}
	}

	statusValue := fromRPCApprovalStatus(req.Decision)
	if statusValue != approvals.StatusApproved && statusValue != approvals.StatusDenied {
		return nil, status.Error(codes.InvalidArgument, "decision must be APPROVED or DENIED")
	}
	if err := s.approvalWF.Decide(ctx, &approvals.Decision{
		RequestID: req.RequestId,
		Status:    statusValue,
		DecidedBy: req.ApproverUserId,
		Notes:     req.Notes,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "decide approval: %v", err)
	}
	return &mcpidsv1.DecideResponse{
		RequestId: req.RequestId,
		Status:    req.Decision,
	}, nil
}

// ListPending returns pending approvals for a tenant.
func (s *Server) ListPending(ctx context.Context, req *mcpidsv1.ListPendingRequest) (*mcpidsv1.ListPendingResponse, error) {
	if s.approvalWF == nil {
		return &mcpidsv1.ListPendingResponse{}, nil
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is required")
	}
	tenantID, err := rpcTenantID(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	req.TenantId = tenantID
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}
	items, err := s.approvalWF.ListPending(ctx, req.TenantId, limit, int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list pending approvals: %v", err)
	}
	out := make([]*mcpidsv1.PendingApproval, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		out = append(out, &mcpidsv1.PendingApproval{
			RequestId: item.ID,
			TenantId:  item.TenantID,
			SessionId: item.SessionID,
			ServerId:  item.ServerID,
			ToolName:  item.ToolName,
			Verdict:   toRPCVerdict(&item.Verdict),
			CreatedAt: item.CreatedAt.UnixMilli(),
			ExpiresAt: item.ExpiresAt.UnixMilli(),
			Status:    toRPCApprovalStatus(item.Status),
		})
	}
	return &mcpidsv1.ListPendingResponse{
		Items: out,
		Total: int32(len(out)),
	}, nil
}

func (s *Server) buildPolicySnapshot(ctx context.Context, tenantID string) (*mcpidsv1.PolicySnapshot, string, error) {
	if s.db == nil {
		return nil, "", status.Error(codes.FailedPrecondition, "database not configured")
	}

	policyRows, err := s.db.Pool().Query(ctx,
		`SELECT id::text, tenant_id::text, name, COALESCE(description, ''),
			 is_dry_run, is_active, priority, default_decision, updated_at
		 FROM policies
		 WHERE tenant_id = $1
		 ORDER BY priority ASC, created_at ASC`,
		tenantID,
	)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "query policies: %v", err)
	}
	defer policyRows.Close()

	var policiesPayload []map[string]any
	var maxUpdated time.Time
	for policyRows.Next() {
		var id, rowTenantID, name, description, defaultDecision string
		var isDryRun, isActive bool
		var priority int
		var updatedAt time.Time
		if err := policyRows.Scan(&id, &rowTenantID, &name, &description, &isDryRun, &isActive, &priority, &defaultDecision, &updatedAt); err != nil {
			return nil, "", status.Errorf(codes.Internal, "scan policy: %v", err)
		}
		mode := "enforce"
		if isDryRun {
			mode = "monitor_only"
		}
		policiesPayload = append(policiesPayload, map[string]any{
			"id":               id,
			"tenant_id":        rowTenantID,
			"name":             name,
			"description":      description,
			"mode":             mode,
			"is_active":        isActive,
			"priority":         priority,
			"default_decision": defaultDecision,
			"updated_at":       updatedAt,
		})
		if updatedAt.After(maxUpdated) {
			maxUpdated = updatedAt
		}
	}
	if policiesPayload == nil {
		policiesPayload = []map[string]any{}
	}

	allRules, err := rules.NewPGStore(s.db.Pool()).LoadRules(ctx)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "load rules: %v", err)
	}
	tenantRules := make([]rules.Rule, 0, len(allRules))
	for _, rule := range allRules {
		if len(rule.Scope.TenantIDs) == 0 || containsString(rule.Scope.TenantIDs, tenantID) {
			tenantRules = append(tenantRules, rule)
		}
	}

	policiesJSON, err := json.Marshal(policiesPayload)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "marshal policies: %v", err)
	}
	rulesJSON, err := json.Marshal(tenantRules)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "marshal rules: %v", err)
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256(append(append([]byte{}, policiesJSON...), rulesJSON...)))
	version := maxUpdated.UnixMilli()
	if version == 0 {
		version = time.Now().UTC().UnixMilli()
	}
	return &mcpidsv1.PolicySnapshot{
		TenantId:     tenantID,
		Version:      version,
		PoliciesJson: policiesJSON,
		RulesJson:    rulesJSON,
	}, checksum, nil
}

func (s *Server) recordRPCEvent(ctx context.Context, ev *mcpidsv1.Event) error {
	if ev == nil {
		return nil
	}

	switch ev.Kind {
	case mcpidsv1.EventKind_EVENT_KIND_SESSION_STARTED,
		mcpidsv1.EventKind_EVENT_KIND_SESSION_ENDED,
		mcpidsv1.EventKind_EVENT_KIND_SESSION_QUARANTINED:
		if s.db != nil && len(ev.PayloadJson) > 0 {
			var sess mcppkg.Session
			if err := json.Unmarshal(ev.PayloadJson, &sess); err == nil {
				if sess.ID == "" {
					sess.ID = ev.SessionId
				}
				if sess.TenantID == "" {
					sess.TenantID = ev.TenantId
				}
				if sess.AgentID == "" {
					sess.AgentID = ev.AgentId
				}
				if sess.ServerID == "" {
					sess.ServerID = ev.ServerId
				}
				if err := sessionpkg.NewPGStore(s.db.Pool()).Save(ctx, &sess); err != nil {
					return status.Errorf(codes.Internal, "record session: %v", err)
				}
			}
		}
	case mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL,
		mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL_BLOCKED,
		mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL_APPROVED,
		mcpidsv1.EventKind_EVENT_KIND_TOOLS_LIST,
		mcpidsv1.EventKind_EVENT_KIND_TOOLS_FILTERED:
		s.recordGraphFromRPCEvent(ctx, ev)
		if s.eventRecorder == nil {
			return nil
		}
		_, err := s.eventRecorder.RecordCall(ctx, eventspkg.CallRecord{
			ID:             ev.EventId,
			SessionID:      ev.SessionId,
			TenantID:       ev.TenantId,
			AgentID:        ev.AgentId,
			ServerID:       ev.ServerId,
			Method:         rpcEventMethod(ev.Kind),
			RequestPayload: ev.PayloadJson,
			Verdict:        ptrFromRPCVerdict(ev.Verdict),
			CalledAt:       rpcEventTime(ev.Timestamp),
		})
		if err != nil {
			return status.Errorf(codes.Internal, "record call: %v", err)
		}
	case mcpidsv1.EventKind_EVENT_KIND_DETECTION:
		if s.eventRecorder == nil {
			return nil
		}
		_, err := s.eventRecorder.RecordDetection(ctx, eventspkg.DetectionRecord{
			CallID:    ev.EventId,
			SessionID: ev.SessionId,
			TenantID:  ev.TenantId,
			ServerID:  ev.ServerId,
			Verdict:   ptrFromRPCVerdict(ev.Verdict),
			Evidence: map[string]any{
				"payload": json.RawMessage(ev.PayloadJson),
			},
			CreatedAt: rpcEventTime(ev.Timestamp),
		})
		if err != nil {
			return status.Errorf(codes.Internal, "record detection: %v", err)
		}
	default:
		if s.eventRecorder == nil {
			return nil
		}
		var payload map[string]any
		if len(ev.PayloadJson) > 0 {
			_ = json.Unmarshal(ev.PayloadJson, &payload)
		}
		if payload == nil {
			payload = map[string]any{}
		}
		payload["event_kind"] = ev.Kind
		if err := s.eventRecorder.RecordAudit(ctx, eventspkg.AuditRecord{
			TenantID:     ev.TenantId,
			ActorID:      ev.AgentId,
			ActorKind:    payloadString(payload, "actor_kind", "agent"),
			Action:       payloadString(payload, "action", "event.publish"),
			ResourceKind: payloadString(payload, "resource_kind", "event"),
			ResourceID:   payloadString(payload, "resource_id", ev.EventId),
			Payload:      payload,
			IPAddress:    payloadString(payload, "ip_address", ""),
		}); err != nil {
			return status.Errorf(codes.Internal, "record audit: %v", err)
		}
	}
	return nil
}

func (s *Server) recordGraphFromRPCEvent(ctx context.Context, ev *mcpidsv1.Event) {
	if s.graphEngine == nil || ev == nil || ev.SessionId == "" || ev.ServerId == "" || len(ev.PayloadJson) == 0 {
		return
	}
	if ev.Kind != mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL &&
		ev.Kind != mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL_BLOCKED &&
		ev.Kind != mcpidsv1.EventKind_EVENT_KIND_TOOL_CALL_APPROVED {
		return
	}

	var msg mcppkg.JSONRPCMessage
	if err := json.Unmarshal(ev.PayloadJson, &msg); err != nil {
		return
	}
	if msg.Method != mcppkg.MethodToolsCall {
		return
	}
	params, err := mcppkg.ParseToolCallParams(msg.Params)
	if err != nil || strings.TrimSpace(params.Name) == "" {
		return
	}

	agentID := ev.AgentId
	if agentID == "" && s.sessionManager != nil {
		if sess, err := s.sessionManager.Get(ctx, ev.SessionId); err == nil && sess != nil {
			agentID = sess.AgentID
		}
	}
	if agentID == "" {
		return
	}

	_ = s.graphEngine.RecordCall(ctx, graph.CallRecord{
		TenantID:  ev.TenantId,
		AgentID:   agentID,
		SessionID: ev.SessionId,
		ServerID:  ev.ServerId,
		ToolName:  params.Name,
		CalledAt:  rpcEventTime(ev.Timestamp),
	})
}

func snapshotChangeSummary(prevChecksum, nextChecksum string) string {
	if prevChecksum == "" {
		return "first snapshot"
	}
	if prevChecksum == nextChecksum {
		return "no capability changes"
	}
	return "tool inventory changed"
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func payloadString(payload map[string]any, key, fallback string) string {
	if payload == nil {
		return fallback
	}
	if value, ok := payload[key].(string); ok && value != "" {
		return value
	}
	return fallback
}

func jsonTextOrDefault(raw []byte, fallback string) string {
	if len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func rpcTenantID(ctx context.Context, requestedTenantID string) (string, error) {
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil || claims.TenantID == "" {
		return requestedTenantID, nil
	}
	if requestedTenantID == "" {
		return claims.TenantID, nil
	}
	if requestedTenantID != claims.TenantID {
		return "", status.Error(codes.PermissionDenied, "tenant scope mismatch")
	}
	return requestedTenantID, nil
}

func rpcEventMethod(kind mcpidsv1.EventKind) string {
	switch kind {
	case mcpidsv1.EventKind_EVENT_KIND_TOOLS_LIST, mcpidsv1.EventKind_EVENT_KIND_TOOLS_FILTERED:
		return "tools/list"
	default:
		return "tools/call"
	}
}

func rpcEventTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Now().UTC()
	}
	return time.UnixMilli(ts).UTC()
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

func ptrFromRPCVerdict(v *mcpidsv1.Verdict) *types.Verdict {
	verdict := fromRPCVerdict(v)
	return &verdict
}

func fromRPCVerdict(v *mcpidsv1.Verdict) types.Verdict {
	if v == nil {
		return types.Verdict{Decision: types.DecisionAllow, Severity: types.SeverityInfo}
	}
	out := types.Verdict{
		Decision:          fromRPCDecision(v.Decision),
		Severity:          fromRPCSeverity(v.Severity),
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

func fromRPCDecision(decision mcpidsv1.Decision) types.Decision {
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

func fromRPCSeverity(severity mcpidsv1.Severity) types.Severity {
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

func toRPCApprovalStatus(statusValue approvals.Status) mcpidsv1.ApprovalStatus {
	switch statusValue {
	case approvals.StatusPending:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_PENDING
	case approvals.StatusApproved:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	case approvals.StatusDenied:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_DENIED
	case approvals.StatusExpired:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_EXPIRED
	default:
		return mcpidsv1.ApprovalStatus_APPROVAL_STATUS_UNSPECIFIED
	}
}

func fromRPCApprovalStatus(statusValue mcpidsv1.ApprovalStatus) approvals.Status {
	switch statusValue {
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_APPROVED:
		return approvals.StatusApproved
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_DENIED:
		return approvals.StatusDenied
	case mcpidsv1.ApprovalStatus_APPROVAL_STATUS_EXPIRED:
		return approvals.StatusExpired
	default:
		return approvals.StatusPending
	}
}
