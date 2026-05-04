<p align="center">
  <img src="docs/assets/mcpids_logo.png" alt="MCPIDS logo" width="760" />
</p>

# MCPIDS

**MCP Intrusion Detection and Prevention System** - an inline security layer that intercepts all traffic between AI agents and MCP servers, inspecting every JSON-RPC message and enforcing policy in real time.

```
AI Agent → [MCPIDS Gateway] → MCP Server
                 ↕
         [Control Plane]
         [Rules Engine]
         [Diff Engine]
         [Risk Engine]
         [Graph Engine]
         [Semantic Service]
         [Approvals Workflow]
```

---

## Why MCPIDS?

MCP servers are a rapidly growing attack surface. They can:

- Embed **prompt injection** instructions in tool descriptions
- **Exfiltrate secrets** returned by tools (API keys, tokens, credentials)
- **Change tool behaviour silently** between versions (supply chain risk)
- Chain tool calls to perform **lateral movement** across systems

MCPIDS sits inline between your AI agent and every MCP server, giving you visibility, control, and auditability over all MCP activity without changing the agent or server.

---

## Features

| Capability | Description |
|-----------|-------------|
| **Inline interception** | Inspects every `tools/list`, `tools/call`, `initialize`, and resource request |
| **Rules engine** | Deterministic phrase/regex/secret pattern matching with built-in threat signatures |
| **Semantic classifier** | Pluggable classifier; local dev uses the built-in stub, Docker/K8s route through `semantic-service` over HTTP with stub fallback |
| **Diff engine** | Detects tool additions, description changes, and schema widening between snapshots |
| **Risk scoring** | Weighted 0.0–1.0 aggregate score from all signal sources |
| **Graph engine** | Detects lateral movement and suspicious call chains, with optional PostgreSQL-backed durable graph storage |
| **Approvals workflow** | Hold-and-notify for human-in-the-loop review of high-risk tool calls |
| **Secret redaction** | Scrubs AWS keys, GitHub tokens, JWTs, PEM blocks, and more from responses |
| **Session quarantine** | Freeze an entire session on detection of critical-severity activity |
| **eBPF sensor** | Optional Linux kernel-level process/network telemetry from packaged tracepoint/ringbuf BPF programs, with `/proc` fallback |
| **Audit trail** | Immutable PostgreSQL log of every call, verdict, and admin action |
| **Multi-tenant** | Tenant-scoped policies, rules, and sessions |

---

## Architecture

Five components - deploy what you need:

| Component | Role |
|-----------|------|
| **Gateway** | Hot-path HTTP reverse proxy. Intercepts all MCP traffic (HTTP/SSE + stdio). |
| **Control Plane** | Policy engine, approvals, incident management. REST API (`:8080`) + gRPC (`:9090`). |
| **Agent** | Endpoint daemon. Discovers local MCP configs, optionally wraps stdio processes. |
| **Semantic Service** | HTTP classifier service used by Docker/K8s deployments (`/healthz`, `/classify`). |
| **eBPF Sensor** | Linux-only. Kernel-level process + network telemetry via kprobes. |

See [`docs/architecture.md`](docs/architecture.md) for the full data flow.

---

## Inspection Pipeline

Every intercepted message runs through (in order):

1. **Schema Validation** - validate tool call arguments against stored JSON Schema
2. **Rules Interceptor** - Aho-Corasick phrase matching + regex + secret patterns
3. **Semantic Interceptor** - local stub in dev configs, or HTTP calls to `semantic-service` in Docker/K8s
4. **Diff Interceptor** - detect capability changes since last snapshot
5. **Risk Interceptor** - aggregate signals into a 0.0–1.0 risk score
6. **Policy Interceptor** - final decision → Verdict

### Verdict precedence

```
quarantine > deny > require_approval > redact > hide > monitor_only > allow
```

Default behaviour: **fail-closed** - pipeline timeout (100ms) → deny.

---

## Quick Start

For a one-command demo that starts a mock MCP server, runs MCPIDS locally, and
prints filtered/redacted outputs plus control-plane state:

```bash
./scripts/demo-local.sh
```

Manual startup:

```bash
# Start backing services (Postgres, Redis, OTel collector)
make docker-up

# Run database migrations
make migrate

# Seed default tenant, policies, and rules
make seed

# Start control plane (REST :8080, gRPC :9090)
make run-control-plane &

# Start gateway (HTTP :8443 → your MCP server)
make run-gateway &

# Verify
curl -s http://localhost:8080/healthz | jq .
curl -s http://localhost:8080/api/v1/dashboard/summary | jq .
```

Point your MCP client (Claude Desktop, Cursor, VS Code) at `http://localhost:8443` instead of your MCP server. All traffic will be intercepted and inspected.

For a containerized stack including `semantic-service`, use:

```bash
make docker-up-all
```

---

## Threat Scenarios

MCPIDS ships with 8 threat scenario fixtures and corresponding tests:

| # | Scenario | Detection Layer | Verdict |
|---|----------|----------------|---------|
| 01 | Tool description: "ignore previous instructions" | Rules: phrase match | `hide` |
| 02 | Tool description instructs silent exfiltration | Rules: exfil phrases | `deny` |
| 03 | Tool response contains injected prompt | Rules: response scan | `redact` |
| 04 | New destructive tool appears after server update | Diff: added tool | `require_approval` |
| 05 | Tool schema widened (`additionalProperties: true`) | Diff: schema change | `require_approval` |
| 06 | `read_secrets` → `post_to_webhook` in same session | Graph: lateral movement | `quarantine` |
| 07 | stdio tool called with `--exec sh -c rm -rf /` | Rules: arg regex | `deny` |
| 08 | Tool description quietly changed | Diff: description change | `require_approval` |

```bash
make test-threats
```

---

## Built-in Detection Signatures

**Suspicious tool phrases** (→ `hide`):
`ignore previous instructions`, `disregard system prompt`, `do not reveal`, `act as`, `you are now`, …

**Exfiltration phrases** (→ `deny`):
`send to`, `upload to`, `POST to`, `exfiltrate`, `without alerting`, `without notifying`, …

**Secret patterns** (→ `redact`):
AWS access keys, GCP tokens, GitHub PATs, Slack tokens, OpenAI keys, JWT tokens, PEM private key blocks

---

## Running Tests

```bash
make test-unit              # unit tests - no Docker required
make test-threats           # all 8 threat scenario tests
make test-integration       # in-process integration tests - no Docker required
make test-integration-infra # Postgres/Redis-backed integration smoke tests via Docker Compose
```

---

## Project Structure

```
cmd/                  Entry points (gateway, control-plane, agent, semantic-service, sensor-ebpf)
internal/
  gateway/            HTTP reverse proxy + inspection pipeline
  policy/rules/       Rules engine with built-in signatures
  diff/               Snapshot comparison and schema widening detection
  risk/               Weighted signal aggregation → risk score
  semantic/           Pluggable semantic classifier (HTTP backend + local stub)
  graph/              Call graph and lateral movement detection (memory + PostgreSQL store)
  approvals/          Hold-and-notify workflow via Redis pub/sub
  session/            Session state machine (Redis-backed)
  controlplane/       REST API + gRPC service plane
  agent/              Local MCP discovery + stdio wrapper
  sensor/             eBPF sensor with ringbuf readers (Linux) + stub (all platforms)
  storage/            PostgreSQL (pgx/v5) + Redis (go-redis v9)
pkg/types/            Exported domain types (Verdict, Decision, MCPServer, …)
policies/             YAML policy files (default, strict, examples)
tests/                Unit + integration tests + 8 threat scenario fixtures
deploy/               Docker Compose + Dockerfiles + Kubernetes manifests
docs/                 Full documentation
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [`docs/architecture.md`](docs/architecture.md) | System overview and data flow |
| [`docs/local-dev.md`](docs/local-dev.md) | Local development guide |
| [`docs/deployment.md`](docs/deployment.md) | Production deployment (Docker, Kubernetes, TLS) |
| [`docs/policy-model.md`](docs/policy-model.md) | Rules, verdicts, risk scoring, approvals |
| [`docs/threat-model.md`](docs/threat-model.md) | Threat actors, scenarios, and mitigations |
| [`docs/api.md`](docs/api.md) | REST API reference |
| [`docs/limitations.md`](docs/limitations.md) | Known limitations and roadmap |
| [`docs/ebpf-support-matrix.md`](docs/ebpf-support-matrix.md) | eBPF kernel/distro support matrix |

---

## Contributing and Security

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
