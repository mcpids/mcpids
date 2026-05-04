# Changelog

All notable project changes are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Community docs, issue/PR templates, and release automation for the first
  public OSS distribution
- Scripted local demo that replays safe and malicious MCP traffic through the
  gateway and queries control-plane state

## [0.1.0] - 2026-04-03

### Added

- Inline MCP gateway for JSON-RPC request/response inspection and enforcement
- Control-plane REST API and gRPC service plane for policy, inventory, events,
  approvals, graph, and session operations
- Rules engine with built-in prompt-injection, exfiltration, secret-redaction,
  and schema-violation signatures
- JSON Schema validation for tool call arguments
- Diff engine for tool snapshot changes and schema widening detection
- Risk scoring and graph-based session chain analysis
- PostgreSQL-backed persistence for sessions, tool snapshots, policies,
  approvals, events, detections, audit records, and graph edges
- Redis-backed session cache and approval pub/sub workflow
- Pluggable semantic classifier with local stub and HTTP backend support
- Agent-side MCP config discovery and stdio wrapping
- Linux eBPF sensor loader with packaged tracepoint/ringbuf process-exec BPF
  source and `/proc` fallback
- Docker Compose and Kubernetes deployment assets
- Unit tests, integration tests, and threat scenario fixtures

[Unreleased]: https://github.com/mcpids/mcpids/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mcpids/mcpids/releases/tag/v0.1.0
