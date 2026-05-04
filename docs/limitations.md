# Known Limitations

This document describes the current limitations of MCPIDS MVP (v0.1.0) and planned improvements for future releases.

---

## 1. eBPF Sensor

### Linux kernel requirement
The eBPF sensor requires **Linux kernel ≥ 5.8** and either `CAP_BPF` + `CAP_PERFMON` (preferred, available since kernel 5.8) or root privileges. On macOS, Windows, and older Linux kernels, the sensor runs as a no-op stub that emits no events.

**Impact**: Kernel-level visibility (process creation, network connections, TLS plaintext capture) is unavailable on non-Linux or older systems.

**Workaround**: Deploy the agent + gateway on a Linux host; use the eBPF sensor only where supported.

**Roadmap**: See `docs/ebpf-support-matrix.md` for the full kernel/distro support matrix.

### eBPF event coverage is still partial
The shipped BPF program currently emits process execution, process exit, and
TCP connect events. `tcp_accept`, `tls_read`, and `tls_write` remain declared in
the event model but are not emitted by the packaged BPF object yet.

**Impact**: Kernel-level process telemetry is available on supported Linux
hosts, but full connection accept and TLS plaintext visibility are not.

**Roadmap**: Add TCP accept and TLS uprobe programs, plus distro-specific
packaging and validation for those attach points.

---

## 2. Semantic Classifier

### Stub fallback remains the default safety net
MCPIDS ships a deterministic local `StubClassifier` and an HTTP/OpenAI-compatible
backend client. If no API token or external model endpoint is configured, the
semantic layer intentionally falls back to the local stub.

**Impact**: Sophisticated prompt injection that avoids known phrases can still
evade the stub fallback path.

**Workaround**: Configure `semantic.provider=openai` or `semantic.provider=http`
with a real classifier endpoint, and keep the rules engine plus approvals
workflow enabled.

**Roadmap**: Add first-party deployment recipes for a hosted classifier backend
and expand model-specific regression tests.

### Async classifier timeout
The semantic interceptor runs asynchronously with a bounded timeout (default: 50ms of the 100ms pipeline budget). Under load, classification may time out and be skipped.

**Impact**: Some messages may pass without semantic classification when the system is under load.

**Workaround**: Rely on the synchronous rules engine as the primary defense layer.

---

## 3. Graph Engine

### Cross-process graph persistence depends on database wiring
The graph engine supports PostgreSQL-backed persistence, and the control plane
can reconstruct graph edges from gRPC tool-call events. If gateway or agent
instances run with `database.url=""` and no service-plane graph reconstruction,
their graph state remains local and non-durable.

**Impact**: Lateral-movement detections can be weaker after process restarts if
graph writes are not persisted.

**Workaround**: In multi-node deployments, enable PostgreSQL persistence via
component database URLs or route tool-call events through the control-plane
gRPC service.

### No persistent cross-session risk scoring
The graph engine supports per-session analysis and `AnalyzeAgent` can query graph state within a session. However, persistent risk scoring across restarts — detecting patterns such as slow exfiltration spread across many short sessions over hours — is not yet implemented.

**Roadmap**: v0.4 will add a time-windowed cross-session graph query with persistent risk accumulation.

---

## 4. Gateway: SSE Stream Interception

### SSE events are buffered per-event
The gateway buffers each SSE event individually for inspection. This adds per-event latency compared to pass-through streaming.

**Impact**: High-throughput SSE streams (e.g., streaming LLM output from an MCP server) may see increased latency of 5–20ms per event.

**Workaround**: Enable `pipeline.monitor_only` for SSE-heavy deployments to reduce enforcement overhead.

### SSE back-pressure not propagated
If the pipeline is slow, the gateway buffers SSE events in memory. Under sustained high throughput, this can cause memory growth.

**Workaround**: Set a reasonable `pipeline.timeout_ms` (default 100ms) and ensure fail-closed is active to drop slow events.

---

## 5. stdio Transport Mode

### Agent must launch the process
The agent's stdio wrapper mode (`wrap_stdio: true`) only intercepts MCP servers that the agent itself launches. Already-running stdio processes (e.g., servers started by the user before MCPIDS was deployed) cannot be wrapped without a restart.

**Impact**: Pre-existing stdio MCP servers are not inspected until they are restarted under the agent.

**Workaround**: Restart all stdio MCP server processes after deploying the agent. Use Cursor/Claude Desktop's server management to reload configurations.

### No stdio interception on Windows
The agent's subprocess pipe interception uses Unix pipe semantics. Windows support is not implemented.

**Roadmap**: v0.3 will add Windows-compatible pipe interception.

---

## 6. TLS

### Upstream TLS is not terminated (pass-through)
The gateway terminates TLS from MCP clients but does **not** perform TLS interception of upstream connections. Traffic between the gateway and the upstream MCP server flows over the upstream's native TLS (or plaintext if the server doesn't use TLS).

**Impact**: The gateway cannot inspect encrypted content in the gateway-to-server leg. Mitigation: if you control the upstream MCP server, configure it to use mTLS with the gateway as the TLS terminator.

### Dev TLS certs are self-signed
The certs generated by `scripts/gen-certs.sh` are self-signed and intended for development only. MCP clients will show trust warnings unless the CA cert is installed.

---

## 7. Control Plane API

The REST and gRPC API surfaces are implemented for the current core workflows
(servers, policies, rules, sessions, detections, incidents, approvals, graph,
and audit). A basic operator dashboard is embedded at `/ui`. What is still
missing is OpenAPI doc generation and API contract automation in CI.

**Impact**: Operators can use the embedded dashboard or REST/gRPC directly.
Programmatic clients have no machine-readable API contract (OpenAPI spec) yet.

**Roadmap**: Add OpenAPI generation and API compatibility checks in CI.

---

## 8. gRPC Service Plane

Gateway, agent, and sensor clients can use the control-plane gRPC service for
policy snapshots, tool snapshots, events, and approvals. The K8s manifests now
ship with mTLS/JWT wiring enabled by default, but operators still need to supply
their own CA, service certificates, JWKS endpoint, issuer/audience values, and
client bearer tokens before applying the manifests. Contract testing across
rolling upgrades is still a separate hardening item.

**Roadmap**: Add cert-manager/JWKS issuer deployment recipes and protobuf
compatibility tests to release CI.

---

## 9. Schema Validation

### Unknown tool schemas are fail-closed
The validator keeps compiled schemas in memory and can hydrate them from the
latest persisted tool snapshot when a schema is missing. If no snapshot exists
yet for a server/tool pair, MCPIDS now denies the `tools/call` request with a
schema violation until the tool is seen in `tools/list`. Tools that are known to
have no input schema remain allowed.

**Impact**: Very first-time servers with no stored snapshot may see early
`tools/call` requests denied until the first `tools/list` response is observed.

**Workaround**: After startup, trigger a `tools/list` call (e.g., via the AI client) to populate the registry before sensitive `tools/call` requests arrive.

---

## 10. Performance

### Tested scale
The MVP has been designed for deployments with:
- Up to 10 concurrent MCP sessions
- Up to 100 tool calls per minute
- Tool lists of up to 200 tools per server

At higher scales, the pipeline latency budget, rule evaluation cost, and graph
query volume may become bottlenecks.

**Roadmap**: Performance profiling and load testing are planned for v0.3.

### Rule evaluation is single-threaded per message
The rules engine evaluates conditions sequentially. Large rule sets (>500 rules) may push pipeline latency above the 100ms budget.

**Workaround**: Keep rule sets focused; use Aho-Corasick phrase matching (O(n) per message, independent of phrase set size) rather than large regex sets.

---

## 11. Multi-Tenancy

### Tenant isolation is logical, not physical
All tenants share the same database, Redis, and gateway processes. Tenant isolation is enforced at the query and policy level. A misconfigured rule or a database privilege escalation could expose cross-tenant data.

**Workaround**: Use separate deployments for high-isolation requirements (e.g., regulated industries).

---

## Summary Table

| Limitation | Severity | Workaround | Roadmap |
|-----------|----------|------------|---------|
| Partial eBPF event coverage | Medium | Use process_exec/process_exit/tcp_connect + gateway signals | Add tcp_accept/TLS probes |
| Stub semantic fallback | Medium | Configure openai/http backend + custom rules | First-party model deployment recipes |
| Graph persistence depends on deployment wiring | Low | Enable DB URLs or control-plane gRPC graph reconstruction | K8s hardening overlays |
| No persistent cross-session risk scoring | Low | Per-session detection only | v0.4 |
| SSE stream latency | Low | monitor_only for SSE servers | Streaming mode |
| stdio requires restart | Low | Restart servers after deploy | v0.3 Windows support |
| No upstream TLS inspection | Medium | mTLS to upstream server | Configurable |
| No OpenAPI spec or CI contract tests | Low | Use embedded /ui dashboard or REST/gRPC directly | OpenAPI generation + CI |
| Unknown-schema calls are denied before first snapshot | Low | Seed tools/list once per server | Persisted schema preloading improvements |
