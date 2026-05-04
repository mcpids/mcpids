# MCPIDS Architecture

## Overview

MCPIDS (MCP Intrusion Detection and Prevention System) is an inline security layer that intercepts all traffic between AI agents and MCP servers. Every JSON-RPC 2.0 message is inspected and a policy decision is made before it is forwarded.

```
AI Agent → [MCPIDS Gateway] → MCP Server
                 ↕
         [Control Plane]
         [Rules Engine]
         [Diff Engine]
         [Risk Engine]
         [Graph Engine]
         [Semantic Classifier]
         [Approvals Workflow]
```

## Components

### Gateway
The hot path. An HTTP reverse proxy (`httputil.ReverseProxy`) that intercepts inbound (client→server) and outbound (server→client) MCP messages. Runs the inspection pipeline for every message. Supports both HTTP/SSE and stdio transports.

**Key files:** `internal/gateway/`

### Control Plane
The policy and administration server. Exposes a REST API (port 8080) for human operators and a gRPC API (port 9090) for gateway/agent clients. Manages policies, sessions, approvals, and incidents.

**Key files:** `internal/controlplane/`, `cmd/control-plane/`

### Agent
The endpoint daemon. Discovers local MCP server configurations (`~/.cursor/mcp.json`, `~/.claude.json`, Claude Desktop config), optionally wraps stdio processes behind the inspection pipeline, and reports inventory to the control plane.

**Key files:** `internal/agent/`, `cmd/agent/`

### eBPF Sensor
Linux kernel-level visibility layer. Observes process creation and network connections via eBPF kprobes. Enriches call records with process and network context. On non-Linux platforms, runs as a no-op stub.

**Key files:** `internal/sensor/`, `cmd/sensor-ebpf/`

## Inspection Pipeline

For every intercepted MCP message, the pipeline runs (in order):

1. **Schema Validation** - validate tool call arguments against stored JSON Schema
2. **Rules Interceptor** - deterministic phrase/regex/secret pattern matching
3. **Semantic Interceptor** - async local stub classifier (no external service required)
4. **Diff Interceptor** - detect capability changes since last snapshot
5. **Risk Interceptor** - aggregate signals into a 0.0–1.0 risk score
6. **Policy Interceptor** - final decision → Verdict

### Verdict Precedence

```
quarantine > deny > require_approval > redact > hide > monitor_only > allow
```

### Fail Behavior

Default: **fail-closed**. Pipeline timeout (100ms default) → deny. Configurable per deployment via `pipeline.fail_open: true`.

## Data Flow

### tools/list (outbound)
1. Upstream returns tool list
2. Snapshot captured → delta computed vs previous
3. Each tool evaluated independently (per-tool verdict)
4. Tools with `hide` decision removed from list
5. Filtered list returned to client

### tools/call (inbound request)
1. Tool call arguments validated against schema
2. Rules engine evaluates tool name and arguments
3. Graph engine checks session history
4. Policy decision:
   - `deny` → JSON-RPC error -32001 returned
   - `require_approval` → held in Redis channel, admin notified, gateway blocks
   - `allow` → forwarded to upstream

### tools/call (outbound response)
1. Response content inspected for secrets and injection phrases
2. `redact` → secrets scrubbed before forwarding
3. `quarantine` → session frozen, all subsequent calls denied

## Storage

- **Redis** - session state (fast lookups), approval hold channels (pub/sub)
- **PostgreSQL** - persistent audit trail, policy rules, incidents, tool snapshots
- **In-memory** - graph engine (MVP; rebuilt from DB on restart), diff snapshots
