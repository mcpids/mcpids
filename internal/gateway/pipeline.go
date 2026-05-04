// Package gateway implements the MCPIDS inline MCP interceptor proxy.
// It sits between AI agents and MCP servers, inspecting every JSON-RPC
// message and enforcing policy decisions in real time.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	approvalspkg "github.com/mcpids/mcpids/internal/approvals"
	"github.com/mcpids/mcpids/internal/diff"
	eventspkg "github.com/mcpids/mcpids/internal/events"
	"github.com/mcpids/mcpids/internal/graph"
	"github.com/mcpids/mcpids/internal/mcp"
	"github.com/mcpids/mcpids/internal/policy"
	schemapkg "github.com/mcpids/mcpids/internal/schema"
	"github.com/mcpids/mcpids/internal/semantic"
	sessionpkg "github.com/mcpids/mcpids/internal/session"
	"github.com/mcpids/mcpids/pkg/types"
)

const (
	// PipelineTimeout is the maximum latency budget for the interception pipeline.
	// Exceeding this returns a fail-closed verdict (deny) unless failOpen is configured.
	PipelineTimeout = 100 * time.Millisecond

	// SemanticTimeout is the budget allocated to the semantic classifier within the pipeline.
	SemanticTimeout = 50 * time.Millisecond
)

// InterceptRequest carries all inputs for one MCP message inspection.
type InterceptRequest struct {
	// Message is the raw JSON-RPC envelope being inspected.
	Message *mcp.JSONRPCMessage

	// Method is the MCP method. Must be set explicitly for responses
	// because JSON-RPC responses do not carry a method field.
	Method string

	// Direction indicates whether this is an inbound (client→server)
	// or outbound (server→client) message.
	Direction mcp.Direction

	// Session is the MCP session context for this message.
	Session *mcp.Session

	// ServerID identifies the upstream MCP server.
	ServerID string
}

// InterceptResult is the enforcement outcome of the pipeline for one message.
type InterceptResult struct {
	// Verdict is the enforcement decision.
	Verdict *types.Verdict

	// ModifiedBody, when non-nil, replaces the original message bytes before forwarding.
	// Set for both blocked messages (error responses) and modified messages (filtered lists).
	ModifiedBody []byte

	// Blocked indicates that the message must NOT be forwarded.
	// The caller should write ModifiedBody (the error response) to the client instead.
	Blocked bool
}

func allowResult() *InterceptResult {
	return &InterceptResult{
		Verdict: &types.Verdict{Decision: types.DecisionAllow, Severity: types.SeverityInfo},
	}
}

func passWithVerdict(verdict *types.Verdict) *InterceptResult {
	if verdict == nil {
		return allowResult()
	}
	return &InterceptResult{Verdict: verdict}
}

func blockWithMsg(verdict *types.Verdict, errMsg *mcp.JSONRPCMessage) *InterceptResult {
	body, _ := mcp.MarshalMessage(errMsg)
	return &InterceptResult{
		Verdict:      verdict,
		ModifiedBody: body,
		Blocked:      true,
	}
}

// Pipeline orchestrates all detection engines for MCP message interception.
// Every MCP message passes through it on the hot path.
// Pipeline is safe for concurrent use.
type Pipeline struct {
	policyEngine     policy.Engine
	diffEngine       diff.Engine
	graphEngine      graph.Engine
	schemaValidator  schemapkg.Validator
	semanticEngine   semantic.Classifier
	sessionManager   sessionpkg.Manager
	approvalWorkflow approvalspkg.Workflow
	eventRecorder    eventspkg.Recorder
	metrics          *PipelineMetrics
	pipelineTimeout  time.Duration
	semanticTimeout  time.Duration
	monitorOnlyMode  bool
	failOpen         bool
}

// PipelineOptions configures the Pipeline. All fields except FailOpen are required.
type PipelineOptions struct {
	Policy    policy.Engine
	Diff      diff.Engine
	Graph     graph.Engine
	Schema    schemapkg.Validator
	Semantic  semantic.Classifier
	Sessions  sessionpkg.Manager
	Approvals approvalspkg.Workflow
	Recorder  eventspkg.Recorder
	Metrics   *PipelineMetrics
	// MaxEvalDuration is the full interception timeout budget.
	MaxEvalDuration time.Duration
	// SemanticTimeout is the sub-budget for semantic classification.
	SemanticTimeout time.Duration
	// MonitorOnlyMode converts blocking decisions to monitor_only.
	MonitorOnlyMode bool
	// FailOpen, when true, passes messages through on pipeline timeout.
	// Default behavior is fail-closed (deny on timeout).
	FailOpen bool
}

// NewPipeline creates a new Pipeline with the given options.
func NewPipeline(opts PipelineOptions) *Pipeline {
	pipelineTimeout := opts.MaxEvalDuration
	if pipelineTimeout <= 0 {
		pipelineTimeout = PipelineTimeout
	}
	semanticTimeout := opts.SemanticTimeout
	if semanticTimeout <= 0 {
		semanticTimeout = SemanticTimeout
	}
	return &Pipeline{
		policyEngine:     opts.Policy,
		diffEngine:       opts.Diff,
		graphEngine:      opts.Graph,
		schemaValidator:  opts.Schema,
		semanticEngine:   opts.Semantic,
		sessionManager:   opts.Sessions,
		approvalWorkflow: opts.Approvals,
		eventRecorder:    opts.Recorder,
		metrics:          opts.Metrics,
		pipelineTimeout:  pipelineTimeout,
		semanticTimeout:  semanticTimeout,
		monitorOnlyMode:  opts.MonitorOnlyMode,
		failOpen:         opts.FailOpen,
	}
}

// SemanticClassifierName returns the name of the active semantic classifier,
// or "none" when semantic classification is disabled.
func (p *Pipeline) SemanticClassifierName() string {
	if p.semanticEngine == nil {
		return "none"
	}
	return p.semanticEngine.Name()
}

// Run processes one MCP message and returns an enforcement decision.
func (p *Pipeline) Run(ctx context.Context, req *InterceptRequest) *InterceptResult {
	start := time.Now()
	pipeCtx, cancel := context.WithTimeout(ctx, p.pipelineTimeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = req.Message.Method
	}
	direction := string(req.Direction)

	// Quarantined sessions are always denied - no further evaluation.
	if req.Session != nil && req.Session.IsBlocked() {
		result := blockWithMsg(
			&types.Verdict{Decision: types.DecisionQuarantine, Severity: types.SeverityCritical},
			mcp.QuarantineResponse(req.Message.ID),
		)
		p.recordMetrics(ctx, method, direction, start, result)
		p.persistResult(ctx, req, method, start, result)
		return result
	}

	var result *InterceptResult
	switch {
	case method == mcp.MethodToolsList && req.Direction == mcp.DirectionOutbound:
		result = p.handleToolsListResponse(pipeCtx, req)

	case method == mcp.MethodToolsCall && req.Direction == mcp.DirectionInbound:
		result = p.handleToolsCallRequest(pipeCtx, req)

	case method == mcp.MethodToolsCall && req.Direction == mcp.DirectionOutbound:
		result = p.handleToolsCallResponse(pipeCtx, req)

	case method == mcp.MethodInitialize && req.Direction == mcp.DirectionOutbound:
		p.recordInitializeResponse(pipeCtx, req)
		result = allowResult()

	case method == mcp.MethodPromptsGet && req.Direction == mcp.DirectionOutbound:
		result = p.handlePromptsGetResponse(pipeCtx, req)

	case method == mcp.MethodResourcesRead && req.Direction == mcp.DirectionInbound:
		result = p.handleResourcesReadRequest(pipeCtx, req)

	case method == mcp.MethodResourcesRead && req.Direction == mcp.DirectionOutbound:
		result = p.handleResourcesReadResponse(pipeCtx, req)

	default:
		result = allowResult()
	}

	if errors.Is(pipeCtx.Err(), context.DeadlineExceeded) {
		if p.failOpen {
			result = allowResult()
		} else {
			result = blockWithMsg(
				&types.Verdict{
					Decision: types.DecisionDeny,
					Severity: types.SeverityHigh,
					Reasons:  []string{"pipeline evaluation timed out"},
				},
				mcp.DenyResponse(req.Message.ID, "pipeline evaluation timed out"),
			)
		}
	}

	p.recordMetrics(ctx, method, direction, start, result)
	p.persistResult(ctx, req, method, start, result)
	return result
}

// recordMetrics emits telemetry for the pipeline run.
func (p *Pipeline) recordMetrics(ctx context.Context, method, direction string, start time.Time, result *InterceptResult) {
	duration := time.Since(start)
	p.metrics.RecordRequest(ctx, method, direction, duration)
	p.metrics.RecordPolicyEvalDuration(ctx, duration)
	if result != nil && result.Verdict != nil {
		p.metrics.RecordVerdict(ctx, result.Verdict)
	}
}

func (p *Pipeline) persistResult(ctx context.Context, req *InterceptRequest, method string, start time.Time, result *InterceptResult) {
	if p.eventRecorder == nil || req == nil || req.Session == nil || req.Message == nil {
		return
	}

	payload, err := mcp.MarshalMessage(req.Message)
	if err != nil {
		return
	}

	call := eventspkg.CallRecord{
		SessionID:  req.Session.ID,
		TenantID:   req.Session.TenantID,
		AgentID:    req.Session.AgentID,
		ServerID:   req.ServerID,
		Method:     method,
		DurationMS: int(time.Since(start).Milliseconds()),
		CalledAt:   start.UTC(),
	}
	if req.Direction == mcp.DirectionInbound {
		call.RequestPayload = payload
		if method == mcp.MethodToolsCall {
			if params, err := mcp.ParseToolCallParams(req.Message.Params); err == nil {
				call.ToolName = params.Name
			}
		}
	} else {
		call.ResponsePayload = payload
		if result != nil && len(result.ModifiedBody) > 0 {
			call.ResponsePayload = result.ModifiedBody
		}
	}
	if result != nil {
		call.Verdict = result.Verdict
	}

	callID, err := p.eventRecorder.RecordCall(ctx, call)
	if err != nil {
		slog.Warn("pipeline: persist call failed", "session", req.Session.ID, "error", err)
		return
	}

	if result == nil || result.Verdict == nil || result.Verdict.Decision == types.DecisionAllow {
		return
	}

	_, err = p.eventRecorder.RecordDetection(ctx, eventspkg.DetectionRecord{
		CallID:    callID,
		SessionID: req.Session.ID,
		TenantID:  req.Session.TenantID,
		ServerID:  req.ServerID,
		Verdict:   result.Verdict,
		Evidence: map[string]any{
			"reasons": result.Verdict.Reasons,
			"method":  method,
		},
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		slog.Warn("pipeline: persist detection failed", "session", req.Session.ID, "error", err)
	}
}

// ─── tools/list outbound response ────────────────────────────────────────────

func (p *Pipeline) handleToolsListResponse(ctx context.Context, req *InterceptRequest) *InterceptResult {
	toolsList, err := mcp.ParseToolsListResult(req.Message.Result)
	if err != nil {
		slog.Warn("pipeline: tools/list parse error", "error", err)
		return allowResult()
	}

	serverID := req.ServerID

	// Record a diff snapshot to detect new or modified tools.
	snapTools := make([]diff.ToolSnapshot, len(toolsList.Tools))
	for i, t := range toolsList.Tools {
		snapTools[i] = diff.MakeToolSnapshot(t.Name, t.Description, t.InputSchema)
	}
	_, delta, _ := p.diffEngine.Snapshot(ctx, serverID, snapTools)

	// Build a set of tool names that are new in this snapshot using the delta,
	// rather than calling IsToolNew (which checks the already-updated tool set).
	newToolNames := make(map[string]bool)
	if delta != nil {
		for _, t := range delta.AddedTools {
			newToolNames[t.Name] = true
		}
	}

	// Evaluate each tool individually; collect those that pass.
	var filtered []mcp.Tool
	toolsHidden := false

	for _, tool := range toolsList.Tools {
		if p.schemaValidator != nil {
			if err := p.schemaValidator.RegisterToolSchema(ctx, serverID, tool.Name, tool.InputSchema); err != nil {
				slog.Warn("pipeline: register tool schema failed",
					"server_id", serverID,
					"tool", tool.Name,
					"error", err)
			}
		}

		var toolIsNew string
		if newToolNames[tool.Name] {
			toolIsNew = tool.Name
		}
		diffSig := p.diffEngine.Signal(delta, toolIsNew)

		fields := map[string]string{
			"tool.name":        tool.Name,
			"tool.description": tool.Description,
		}
		if len(tool.InputSchema) > 0 {
			fields["tool.input_schema"] = string(tool.InputSchema)
		}

		semResult := p.classifyContent(ctx, tool.Description, semantic.ContentTypeToolDescription)

		decReq := policy.DecisionRequest{
			VerdictCtx: types.VerdictContext{
				TenantID:  req.Session.TenantID,
				AgentID:   req.Session.AgentID,
				SessionID: req.Session.ID,
				ServerID:  serverID,
				Method:    mcp.MethodToolsList,
				Direction: string(mcp.DirectionOutbound),
			},
			Fields:            fields,
			DiffSignal:        diffSig,
			SemanticResult:    semResult,
			IsMonitorOnlyMode: p.monitorOnlyMode,
		}

		verdict, err := p.policyEngine.Decide(ctx, decReq)
		if err != nil {
			slog.Warn("pipeline: policy error for tool", "tool", tool.Name, "error", err)
			verdict = &types.Verdict{Decision: types.DecisionAllow}
		}

		if verdict.Decision == types.DecisionHide {
			slog.Info("pipeline: tool hidden",
				"tool", tool.Name,
				"session", req.Session.ID,
				"reasons", verdict.Reasons)
			toolsHidden = true
			continue
		}

		filtered = append(filtered, tool)
	}

	if !toolsHidden {
		return allowResult()
	}

	body, err := mcp.RebuildToolsListResult(req.Message, toolsList, filtered)
	if err != nil {
		slog.Warn("pipeline: tools/list rebuild error", "error", err)
		return allowResult()
	}

	return &InterceptResult{
		Verdict: &types.Verdict{
			Decision: types.DecisionHide,
			Severity: types.SeverityMedium,
		},
		ModifiedBody: body,
	}
}

// ─── tools/call inbound request ──────────────────────────────────────────────

func (p *Pipeline) handleToolsCallRequest(ctx context.Context, req *InterceptRequest) *InterceptResult {
	params, err := mcp.ParseToolCallParams(req.Message.Params)
	if err != nil {
		slog.Warn("pipeline: tools/call params parse error", "error", err)
		return allowResult()
	}

	serverID := req.ServerID
	p.metrics.RecordToolCall(ctx, params.Name)

	isNew := p.diffEngine.IsToolNew(ctx, serverID, params.Name)
	var diffSig *diff.Signal
	if isNew {
		diffSig = p.diffEngine.Signal(nil, params.Name)
	}

	fields := map[string]string{"tool.name": params.Name}
	if len(params.Arguments) > 0 {
		fields["tool.arguments"] = string(params.Arguments)
		flattenJSONFields("args", params.Arguments, fields)
	}

	if p.schemaValidator != nil {
		schemaResult := p.schemaValidator.ValidateToolCall(ctx, serverID, params.Name, params.Arguments)
		if !schemaResult.Valid {
			fields["tool.schema_violation"] = schemaResult.Reason
		}
	}

	semResult := p.classifyContent(ctx, string(params.Arguments), semantic.ContentTypeText)
	graphSig := p.recordToolCallGraph(ctx, req.Session, serverID, params.Name)

	decReq := policy.DecisionRequest{
		VerdictCtx: types.VerdictContext{
			TenantID:  req.Session.TenantID,
			AgentID:   req.Session.AgentID,
			SessionID: req.Session.ID,
			ServerID:  serverID,
			Method:    mcp.MethodToolsCall,
			Direction: string(mcp.DirectionInbound),
		},
		Fields:            fields,
		DiffSignal:        diffSig,
		GraphSignal:       graphSig,
		SemanticResult:    semResult,
		IsMonitorOnlyMode: p.monitorOnlyMode,
	}

	verdict, err := p.policyEngine.Decide(ctx, decReq)
	if err != nil {
		slog.Warn("pipeline: policy decision error", "tool", params.Name, "error", err)
		return allowResult()
	}

	switch verdict.Decision {
	case types.DecisionDeny:
		return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, firstReason(verdict.Reasons)))

	case types.DecisionQuarantine:
		p.quarantineSession(ctx, req.Session.ID, verdict)
		return blockWithMsg(verdict, mcp.QuarantineResponse(req.Message.ID))

	case types.DecisionRequireApproval:
		return p.waitForApproval(ctx, req, params, verdict)

	default:
		return passWithVerdict(verdict)
	}
}

// ─── tools/call outbound response ────────────────────────────────────────────

func (p *Pipeline) handleToolsCallResponse(ctx context.Context, req *InterceptRequest) *InterceptResult {
	result, err := mcp.ParseToolCallResult(req.Message.Result)
	if err != nil {
		slog.Warn("pipeline: tools/call result parse error", "error", err)
		return allowResult()
	}

	contentStr := mcp.ExtractTextContent(result)
	semResult := p.classifyContent(ctx, contentStr, semantic.ContentTypeToolOutput)

	decReq := policy.DecisionRequest{
		VerdictCtx: types.VerdictContext{
			TenantID:  req.Session.TenantID,
			AgentID:   req.Session.AgentID,
			SessionID: req.Session.ID,
			ServerID:  req.ServerID,
			Method:    mcp.MethodToolsCall,
			Direction: string(mcp.DirectionOutbound),
		},
		Fields: map[string]string{
			"result.text":    contentStr,
			"result.content": contentStr,
		},
		SemanticResult:    semResult,
		GraphSignal:       p.currentGraphSignal(ctx, req.Session),
		IsMonitorOnlyMode: p.monitorOnlyMode,
	}

	verdict, err := p.policyEngine.Decide(ctx, decReq)
	if err != nil {
		slog.Warn("pipeline: policy decision error for response", "error", err)
		return allowResult()
	}

	switch verdict.Decision {
	case types.DecisionRedact:
		redacted := applyRedactions(result, verdict.Redactions)
		body, err := mcp.RebuildToolCallResult(req.Message, redacted)
		if err != nil {
			slog.Warn("pipeline: redact rebuild error", "error", err)
			return allowResult()
		}
		return &InterceptResult{Verdict: verdict, ModifiedBody: body}

	case types.DecisionDeny:
		return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, firstReason(verdict.Reasons)))

	case types.DecisionQuarantine:
		p.quarantineSession(ctx, req.Session.ID, verdict)
		return blockWithMsg(verdict, mcp.QuarantineResponse(req.Message.ID))

	default:
		return passWithVerdict(verdict)
	}
}

// ─── initialize outbound response ────────────────────────────────────────────

func (p *Pipeline) recordInitializeResponse(ctx context.Context, req *InterceptRequest) {
	result, err := mcp.ParseInitializeResult(req.Message.Result)
	if err != nil {
		slog.Warn("pipeline: initialize result parse error", "error", err)
		return
	}

	slog.Info("pipeline: server initialized",
		"server", result.ServerInfo.Name,
		"version", result.ServerInfo.Version,
		"protocol", result.ProtocolVersion,
		"session", req.Session.ID)

	if p.sessionManager != nil {
		_ = p.sessionManager.UpdateState(ctx, req.Session.ID, mcp.StateReady, "")
	}
}

// ─── prompts/get outbound response ───────────────────────────────────────────

func (p *Pipeline) handlePromptsGetResponse(ctx context.Context, req *InterceptRequest) *InterceptResult {
	var result mcp.PromptsGetResult
	if err := json.Unmarshal(req.Message.Result, &result); err != nil {
		return allowResult()
	}

	var sb strings.Builder
	for _, msg := range result.Messages {
		if msg.Content.Type == "text" {
			sb.WriteString(msg.Content.Text)
			sb.WriteByte('\n')
		}
	}

	semResult := p.classifyContent(ctx, sb.String(), semantic.ContentTypePrompt)
	if semResult != nil && semResult.RiskScore > 0.7 {
		slog.Warn("pipeline: high-risk prompt content detected",
			"session", req.Session.ID,
			"risk_score", semResult.RiskScore,
			"labels", semResult.LabelNames())
	}

	return allowResult()
}

// ─── resources/read inbound request ──────────────────────────────────────────

func (p *Pipeline) handleResourcesReadRequest(ctx context.Context, req *InterceptRequest) *InterceptResult {
	params, err := mcp.ParseResourcesReadParams(req.Message.Params)
	if err != nil {
		return allowResult()
	}
	if p.graphEngine != nil && req.Session != nil {
		_ = p.graphEngine.RecordResourceAccess(ctx, graph.ResourceAccessRecord{
			TenantID:    req.Session.TenantID,
			AgentID:     req.Session.AgentID,
			SessionID:   req.Session.ID,
			ServerID:    req.ServerID,
			ResourceURI: params.URI,
			AccessedAt:  time.Now().UTC(),
		})
	}
	return allowResult()
}

// ─── resources/read outbound response ────────────────────────────────────────

func (p *Pipeline) handleResourcesReadResponse(ctx context.Context, req *InterceptRequest) *InterceptResult {
	result, err := mcp.ParseResourcesReadResult(req.Message.Result)
	if err != nil {
		return allowResult()
	}

	var sb strings.Builder
	for _, c := range result.Contents {
		if c.Text != "" {
			sb.WriteString(c.Text)
			sb.WriteByte('\n')
		}
	}
	contentStr := sb.String()

	semResult := p.classifyContent(ctx, contentStr, semantic.ContentTypeText)

	decReq := policy.DecisionRequest{
		VerdictCtx: types.VerdictContext{
			TenantID:  req.Session.TenantID,
			AgentID:   req.Session.AgentID,
			SessionID: req.Session.ID,
			ServerID:  req.ServerID,
			Method:    mcp.MethodResourcesRead,
			Direction: string(mcp.DirectionOutbound),
		},
		Fields: map[string]string{
			"result.text":    contentStr,
			"result.content": contentStr,
		},
		SemanticResult: semResult,
	}

	verdict, err := p.policyEngine.Decide(ctx, decReq)
	if err != nil {
		return allowResult()
	}

	if verdict.Decision == types.DecisionDeny {
		return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, firstReason(verdict.Reasons)))
	}

	return passWithVerdict(verdict)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (p *Pipeline) classifyContent(ctx context.Context, content string, ctype semantic.ContentType) *semantic.Result {
	if p.semanticEngine == nil || content == "" {
		return nil
	}
	semCtx, cancel := context.WithTimeout(ctx, p.semanticTimeout)
	defer cancel()
	result, err := p.semanticEngine.Classify(semCtx, semantic.ClassifyRequest{
		Content:     content,
		ContentType: ctype,
	})
	if err != nil {
		return nil
	}
	return result
}

func (p *Pipeline) recordToolCallGraph(ctx context.Context, sess *mcp.Session, serverID, toolName string) *graph.Signal {
	if p.graphEngine == nil || sess == nil {
		return nil
	}
	if err := p.graphEngine.RecordCall(ctx, graph.CallRecord{
		TenantID:  sess.TenantID,
		AgentID:   sess.AgentID,
		SessionID: sess.ID,
		ServerID:  serverID,
		ToolName:  toolName,
		CalledAt:  time.Now().UTC(),
	}); err != nil {
		slog.Warn("pipeline: graph record call failed", "session", sess.ID, "tool", toolName, "error", err)
		return nil
	}
	return p.currentGraphSignal(ctx, sess)
}

func (p *Pipeline) currentGraphSignal(ctx context.Context, sess *mcp.Session) *graph.Signal {
	if p.graphEngine == nil || sess == nil {
		return nil
	}
	sig, err := p.graphEngine.Analyze(ctx, sess.TenantID, sess.ID)
	if err != nil {
		slog.Warn("pipeline: graph analyze failed", "session", sess.ID, "error", err)
		return nil
	}
	return sig
}

func flattenJSONFields(prefix string, raw json.RawMessage, fields map[string]string) {
	if len(raw) == 0 {
		return
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return
	}
	flattenAny(prefix, value, fields)
}

func flattenAny(prefix string, value any, fields map[string]string) {
	switch t := value.(type) {
	case map[string]any:
		for key, child := range t {
			flattenAny(prefix+"."+key, child, fields)
		}
	case []any:
		encoded, err := json.Marshal(t)
		if err == nil {
			fields[prefix] = string(encoded)
		}
	case string:
		fields[prefix] = t
	case float64, bool:
		fields[prefix] = strings.TrimSpace(strings.Trim(fmt.Sprintf("%v", t), "\""))
	case nil:
		return
	default:
		fields[prefix] = strings.TrimSpace(strings.Trim(fmt.Sprintf("%v", t), "\""))
	}
}

func (p *Pipeline) quarantineSession(ctx context.Context, sessionID string, verdict *types.Verdict) {
	if p.sessionManager == nil {
		return
	}
	reason := "policy verdict: quarantine"
	if len(verdict.Reasons) > 0 {
		reason = verdict.Reasons[0]
	}
	if err := p.sessionManager.Quarantine(ctx, sessionID, reason); err != nil {
		slog.Warn("pipeline: quarantine session failed", "session", sessionID, "error", err)
	}
	p.metrics.RecordSessionQuarantined(ctx)
}

func (p *Pipeline) waitForApproval(ctx context.Context, req *InterceptRequest, params *mcp.ToolCallParams, verdict *types.Verdict) *InterceptResult {
	if p.approvalWorkflow == nil {
		slog.Warn("pipeline: require_approval verdict but no workflow configured, allowing",
			"tool", params.Name)
		return allowResult()
	}

	raw, _ := json.Marshal(req.Message)
	approvalReq := &approvalspkg.Request{
		TenantID:   req.Session.TenantID,
		AgentID:    req.Session.AgentID,
		SessionID:  req.Session.ID,
		ServerID:   req.ServerID,
		ToolName:   params.Name,
		RawPayload: raw,
		Verdict:    types.Verdict{Decision: types.DecisionRequireApproval, Severity: verdict.Severity},
	}

	requestID, err := p.approvalWorkflow.Submit(ctx, approvalReq)
	if err != nil {
		slog.Warn("pipeline: approval submit failed, denying", "error", err)
		return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, "approval submission failed"))
	}

	p.metrics.RecordApprovalCreated(ctx)
	slog.Info("pipeline: waiting for approval", "request_id", requestID, "tool", params.Name)

	decision, err := p.approvalWorkflow.WaitForDecision(ctx, requestID)
	p.metrics.RecordApprovalResolved(ctx)
	if err != nil {
		if err == types.ErrApprovalDenied {
			return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, "request denied by reviewer"))
		}
		return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, "approval timed out"))
	}

	if decision.Status == approvalspkg.StatusApproved {
		slog.Info("pipeline: approval granted", "request_id", requestID, "decided_by", decision.DecidedBy)
		return allowResult()
	}

	return blockWithMsg(verdict, mcp.DenyResponse(req.Message.ID, "request denied by reviewer"))
}

// applyRedactions applies compiled regex substitutions to a ToolCallResult.
func applyRedactions(result *mcp.ToolCallResult, redactions []types.Redaction) *mcp.ToolCallResult {
	if len(redactions) == 0 {
		return result
	}

	type compiledRedaction struct {
		re          *regexp.Regexp
		replacement string
	}

	compiled := make([]compiledRedaction, 0, len(redactions))
	for _, r := range redactions {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			slog.Warn("pipeline: invalid redaction pattern", "pattern", r.Pattern, "error", err)
			continue
		}
		compiled = append(compiled, compiledRedaction{re: re, replacement: r.Replacement})
	}

	newContent := make([]mcp.ContentBlock, len(result.Content))
	copy(newContent, result.Content)

	for i := range newContent {
		if newContent[i].Type != "text" {
			continue
		}
		text := newContent[i].Text
		for _, cr := range compiled {
			text = cr.re.ReplaceAllString(text, cr.replacement)
		}
		newContent[i].Text = text
	}

	return &mcp.ToolCallResult{Content: newContent, IsError: result.IsError}
}

func firstReason(reasons []string) string {
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}
