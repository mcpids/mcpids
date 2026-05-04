# REST API Reference

Base URL: `http://localhost:8080` (control plane)

All endpoints return JSON. Error responses use `{"error": "message"}`.

Authentication: `Authorization: Bearer <jwt-token>` (required in production; optional in dev with `auth.disabled: true`).

---

## Health

### GET /healthz

Returns component liveness status.

**Response 200**
```json
{
  "status": "ok",
  "component": "control-plane"
}
```

---

### GET /readyz

Returns component readiness (all backing services reachable).

**Response 200**
```json
{
  "status": "ready"
}
```

**Response 503** - backing service unavailable
```json
{
  "error": "database not ready"
}
```

---

## Dashboard

### GET /api/v1/dashboard/summary

Returns aggregate counts for the dashboard overview.

**Response 200**
```json
{
  "active_sessions": 12,
  "pending_approvals": 3,
  "recent_incidents": 1,
  "detections_24h": 47
}
```

---

### GET /api/v1/dashboard/risky-servers

Returns MCP servers sorted by current risk score descending.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `limit` | int | 10 | Max results |

**Response 200**
```json
{
  "servers": [
    {
      "id": "srv-abc123",
      "name": "file-system-tools",
      "url": "stdio://file-tools",
      "trust_score": 0.3,
      "risk_score": 0.82,
      "last_seen_at": "2025-11-25T14:30:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/v1/dashboard/changed-tools

Returns tools whose descriptions or schemas have changed since the last snapshot.

**Response 200**
```json
{
  "changes": [
    {
      "server_id": "srv-abc123",
      "tool_name": "read_file",
      "change_type": "description_changed",
      "old_description": "Read a file.",
      "new_description": "Read a file and send its contents.",
      "detected_at": "2025-11-25T14:20:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/v1/dashboard/pending-approvals

Returns a summary of approvals currently awaiting a decision.

**Response 200**
```json
{
  "pending": [
    {
      "id": "apr-xyz789",
      "tool_name": "delete_all_files",
      "session_id": "sess-123",
      "created_at": "2025-11-25T14:25:00Z",
      "expires_at": "2025-11-25T14:35:00Z"
    }
  ],
  "total": 1
}
```

---

## MCP Servers

### GET /api/v1/servers

List registered MCP servers.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `status` | string | (all) | active \| inactive |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response 200**
```json
{
  "servers": [
    {
      "id": "srv-abc123",
      "tenant_id": "tenant-prod",
      "name": "filesystem-tools",
      "url": "stdio://file-tools",
      "transport": "stdio",
      "trust_score": 0.7,
      "status": "active",
      "first_seen_at": "2025-11-01T00:00:00Z",
      "last_seen_at": "2025-11-25T14:30:00Z"
    }
  ],
  "total": 1
}
```

---

### POST /api/v1/servers

Register a new MCP server.

**Request Body**
```json
{
  "tenant_id": "tenant-prod",
  "name": "my-tools-server",
  "url": "http://tools.internal:3000",
  "transport": "http",
  "trust_score": 0.5
}
```

**Response 201**
```json
{
  "id": "srv-newid",
  "name": "my-tools-server",
  "url": "http://tools.internal:3000"
}
```

---

### GET /api/v1/servers/{id}

Get details for a specific MCP server.

**Response 200** - same schema as list item with additional fields:
```json
{
  "id": "srv-abc123",
  "name": "filesystem-tools",
  "capabilities": {
    "tools": true,
    "prompts": false,
    "resources": true
  },
  "current_tool_count": 12,
  "detection_count_7d": 3
}
```

**Response 404**
```json
{"error": "server not found"}
```

---

### GET /api/v1/servers/{id}/tools

List current tools for a server (from latest snapshot).

**Response 200**
```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read a file from the filesystem.",
      "input_schema": {
        "type": "object",
        "properties": {
          "path": {"type": "string"}
        },
        "required": ["path"]
      }
    }
  ],
  "snapshot_at": "2025-11-25T14:20:00Z",
  "total": 1
}
```

---

### GET /api/v1/servers/{id}/diffs

List tool snapshot diffs for a server.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | RFC3339 | (all) | Filter diffs after this timestamp |
| `limit` | int | 20 | Max results |

**Response 200**
```json
{
  "diffs": [
    {
      "id": "diff-001",
      "server_id": "srv-abc123",
      "detected_at": "2025-11-25T14:20:00Z",
      "added_tools": ["new_dangerous_tool"],
      "removed_tools": [],
      "changed_descriptions": ["read_file"],
      "widened_schemas": [],
      "risk_score": 0.75
    }
  ],
  "total": 1
}
```

---

## Policy & Rules

### GET /api/v1/policies

List policies for a tenant.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (required) | Tenant to query |
| `active` | bool | (all) | Filter by active status |

**Response 200**
```json
{
  "policies": [
    {
      "id": "pol-default",
      "tenant_id": "tenant-prod",
      "name": "Default Policy",
      "is_active": true,
      "is_dry_run": false,
      "priority": 1,
      "default_decision": "allow",
      "created_at": "2025-11-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

---

### POST /api/v1/policies

Create a new policy.

**Request Body**
```json
{
  "tenant_id": "tenant-prod",
  "name": "Strict Production Policy",
  "is_active": true,
  "is_dry_run": false,
  "priority": 1,
  "default_decision": "allow",
  "settings": {
    "monitor_only": false,
    "risk_thresholds": {
      "require_approval": 0.6,
      "quarantine": 0.85
    }
  }
}
```

**Response 201**
```json
{
  "id": "pol-newid",
  "name": "Strict Production Policy"
}
```

---

### PATCH /api/v1/policies/{id}

Update a policy (partial update).

**Request Body** - any subset of policy fields
```json
{
  "is_active": false
}
```

**Response 200**
```json
{"status": "updated", "id": "pol-abc123"}
```

---

### DELETE /api/v1/policies/{id}

Delete a policy (soft delete - audit trail preserved).

**Response 200**
```json
{"status": "deleted", "id": "pol-abc123"}
```

---

### GET /api/v1/rules

List rules.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `policy_id` | string | (all) | Filter by policy |
| `tag` | string | (all) | Filter by tag |
| `enabled` | bool | (all) | Filter by enabled status |
| `limit` | int | 50 | Max results |

**Response 200**
```json
{
  "rules": [
    {
      "id": "rule-001",
      "name": "Block injection phrases",
      "priority": 10,
      "enabled": true,
      "scope": {
        "methods": ["tools/list"],
        "directions": ["outbound"]
      },
      "conditions": [
        {
          "field": "tool.description",
          "op": "phrase_match",
          "value": "suspicious_tool_phrases"
        }
      ],
      "action": {
        "decision": "hide"
      },
      "severity": "high",
      "tags": ["prompt-injection"]
    }
  ],
  "total": 1
}
```

---

### POST /api/v1/rules

Create a new rule.

**Request Body** - see rule schema in `docs/policy-model.md`

**Response 201**
```json
{"id": "rule-newid", "name": "My Rule"}
```

---

### PATCH /api/v1/rules/{id}

Update a rule (partial update).

**Response 200**
```json
{"status": "updated", "id": "rule-abc123"}
```

---

## Sessions

### GET /api/v1/sessions

List active MCP sessions.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `state` | string | (all) | ready \| quarantined \| closed |
| `server_id` | string | (all) | Filter by MCP server |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response 200**
```json
{
  "sessions": [
    {
      "id": "sess-abc123",
      "tenant_id": "tenant-prod",
      "agent_id": "agent-001",
      "mcp_server_id": "srv-abc123",
      "state": "ready",
      "transport": "http",
      "client_name": "claude-desktop",
      "server_name": "filesystem-tools",
      "call_count": 42,
      "started_at": "2025-11-25T14:00:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/v1/sessions/{id}

Get full details for a session including call timeline.

**Response 200**
```json
{
  "id": "sess-abc123",
  "state": "quarantined",
  "quarantine_reason": "lateral movement detected",
  "calls": [
    {
      "id": "call-001",
      "tool_name": "read_secrets",
      "verdict": {"decision": "allow", "severity": "low"},
      "duration_ms": 12,
      "called_at": "2025-11-25T14:05:00Z"
    }
  ]
}
```

---

### POST /api/v1/sessions/{id}/quarantine

Manually quarantine a session.

**Request Body**
```json
{
  "reason": "suspicious activity observed by operator"
}
```

**Response 200**
```json
{
  "status": "quarantined",
  "session_id": "sess-abc123"
}
```

**Response 404**
```json
{"error": "session not found"}
```

---

## Detections & Incidents

### GET /api/v1/detections

List detection events.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `severity` | string | (all) | info \| low \| medium \| high \| critical |
| `session_id` | string | (all) | Filter by session |
| `since` | RFC3339 | (24h ago) | Start time |
| `until` | RFC3339 | (now) | End time |
| `limit` | int | 50 | Max results |

**Response 200**
```json
{
  "detections": [
    {
      "id": "det-001",
      "session_id": "sess-abc123",
      "rule_ids": ["builtin:block-exfil-phrases"],
      "semantic_labels": ["exfiltration"],
      "risk_score": 0.85,
      "severity": "critical",
      "evidence": {
        "field": "tool.description",
        "matched_phrase": "send to",
        "snippet": "...send to attacker.com without..."
      },
      "created_at": "2025-11-25T14:10:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/v1/incidents

List security incidents.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `status` | string | (all) | open \| investigating \| resolved \| closed |
| `severity` | string | (all) | Severity filter |
| `limit` | int | 50 | Max results |

**Response 200**
```json
{
  "incidents": [
    {
      "id": "inc-001",
      "title": "Lateral movement detected in session sess-abc123",
      "severity": "critical",
      "status": "open",
      "created_at": "2025-11-25T14:10:00Z"
    }
  ],
  "total": 1
}
```

---

### POST /api/v1/incidents

Manually create an incident.

**Request Body**
```json
{
  "tenant_id": "tenant-prod",
  "title": "Suspected prompt injection",
  "description": "Tool description contained injection phrase, manual review required.",
  "severity": "high",
  "detection_ids": ["det-001", "det-002"],
  "session_ids": ["sess-abc123"]
}
```

**Response 201**
```json
{"id": "inc-newid", "title": "Suspected prompt injection"}
```

---

### PATCH /api/v1/incidents/{id}

Update incident status, assignee, or notes.

**Request Body**
```json
{
  "status": "investigating",
  "assigned_to": "alice@example.com",
  "notes": "Reviewing call timeline."
}
```

**Response 200**
```json
{"status": "updated", "id": "inc-001"}
```

---

### GET /api/v1/incidents/{id}/evidence

Download the evidence bundle for an incident (all related detection events, call payloads, session timeline).

**Response 200**
```json
{
  "incident_id": "inc-001",
  "detections": [...],
  "calls": [...],
  "sessions": [...],
  "graph_paths": [...]
}
```

---

## Approvals

### GET /api/v1/approvals

List pending approvals.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `status` | string | `pending` | pending \| approved \| denied \| expired |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response 200**
```json
{
  "approvals": [
    {
      "id": "apr-xyz789",
      "tenant_id": "tenant-prod",
      "session_id": "sess-abc123",
      "server_id": "srv-abc123",
      "tool_name": "delete_all_files",
      "verdict": {
        "decision": "require_approval",
        "severity": "critical",
        "reasons": ["new destructive tool detected"]
      },
      "status": "pending",
      "created_at": "2025-11-25T14:25:00Z",
      "expires_at": "2025-11-25T14:35:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/v1/approvals/{id}

Get approval detail including the full raw tool call payload.

**Response 200**
```json
{
  "id": "apr-xyz789",
  "tool_name": "delete_all_files",
  "raw_payload": {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "delete_all_files",
      "arguments": {"path": "/home/user/documents"}
    }
  },
  "verdict": {
    "decision": "require_approval",
    "severity": "critical",
    "matched_rules": ["builtin:new-tool-require-approval"],
    "reasons": ["Tool delete_all_files has not been seen before"]
  },
  "status": "pending",
  "expires_at": "2025-11-25T14:35:00Z"
}
```

**Response 404**
```json
{"error": "approval not found"}
```

---

### POST /api/v1/approvals/{id}/decide

Submit an approve or deny decision.

**Request Body**
```json
{
  "status": "denied",
  "decided_by": "alice@example.com",
  "notes": "This tool should not be called without explicit user confirmation."
}
```

| Field | Required | Values |
|-------|----------|--------|
| `status` | Yes | `approved` \| `denied` |
| `decided_by` | Yes | Operator identifier (email or ID) |
| `notes` | No | Free-text rationale |

**Response 200**
```json
{
  "status": "denied",
  "request_id": "apr-xyz789"
}
```

**Response 400** - already decided
```json
{"error": "approval already decided"}
```

**Response 400** - invalid status
```json
{"error": "status must be 'approved' or 'denied'"}
```

**Response 503** - approval workflow not configured (no Redis)
```json
{"error": "approval workflow not configured"}
```

---

## Graph

### GET /api/v1/graph/sessions/{id}

Get the call graph for a session.

**Response 200**
```json
{
  "session_id": "sess-abc123",
  "nodes": [
    {"id": "n1", "kind": "agent", "label": "claude-desktop"},
    {"id": "n2", "kind": "tool", "label": "read_file"},
    {"id": "n3", "kind": "tool", "label": "post_to_webhook"},
    {"id": "n4", "kind": "server", "label": "filesystem-tools"}
  ],
  "edges": [
    {"from": "n1", "to": "n2", "kind": "called", "weight": 1.0},
    {"from": "n1", "to": "n3", "kind": "called", "weight": 1.0},
    {"from": "n2", "to": "n4", "kind": "served_by", "weight": 1.0}
  ]
}
```

---

### GET /api/v1/graph/agents/{id}

Get all graph edges for an agent within a time window.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | RFC3339 | (1h ago) | Start of time window |
| `until` | RFC3339 | (now) | End of time window |

**Response 200** - same format as session graph

---

## Audit

### GET /api/v1/audit

Paginated audit trail of all admin API actions.

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | (all) | Filter by tenant |
| `actor_id` | string | (all) | Filter by actor |
| `action` | string | (all) | e.g., `approval.decided`, `session.quarantined` |
| `since` | RFC3339 | (24h ago) | Start time |
| `until` | RFC3339 | (now) | End time |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response 200**
```json
{
  "events": [
    {
      "id": "evt-001",
      "tenant_id": "tenant-prod",
      "actor_id": "user-alice",
      "actor_kind": "user",
      "action": "approval.decided",
      "resource_kind": "approval",
      "resource_id": "apr-xyz789",
      "payload": {
        "status": "denied",
        "decided_by": "alice@example.com"
      },
      "ip_address": "192.168.1.100",
      "created_at": "2025-11-25T14:30:00Z"
    }
  ],
  "total": 1
}
```

---

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Bad request - invalid body or missing required field |
| 401 | Unauthorized - missing or invalid JWT |
| 403 | Forbidden - insufficient RBAC role |
| 404 | Not found |
| 501 | Not implemented (MVP stub) |
| 503 | Service unavailable - backing service unreachable |

All errors return `{"error": "description"}`.

---

## CORS

The control plane REST API allows cross-origin requests from any origin (`Access-Control-Allow-Origin: *`). In production, restrict this to your dashboard domain via the `cors.allowed_origins` config.

---

## Rate Limiting

Admin API endpoints are rate-limited per source IP:
- Default: 100 requests/second per IP
- Approval decisions: 10 requests/second per IP

Configure via `controlplane.rate_limit` in the config file.
