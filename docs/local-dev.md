# Local Development Guide

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Go | 1.23 | Build and test |
| Docker + Docker Compose | 24.x | Postgres, Redis, OTel collector |
| Make | 3.81+ | Build automation |
| buf | 1.30+ | Protobuf code generation |
| golangci-lint | 1.57+ | Static analysis |

Optional:
- `jq` - pretty-print JSON from API calls
- `grpcurl` - test gRPC endpoints
- `openssl` - generate dev TLS certs

## Quick Start (5 minutes)

```bash
# 1. Clone and enter the repo
git clone https://github.com/mcpids/mcpids
cd mcpids

# 2. Start backing services
make docker-up

# 3. Run database migrations
make migrate

# 4. Seed default tenant, policies, and rules
make seed

# 5. Start control plane (REST :8080, gRPC :9090)
make run-control-plane &

# 6. Start gateway (HTTP :8443 → upstream :3000)
make run-gateway &

# 7. Verify everything is healthy
curl -s http://localhost:8080/healthz | jq .
curl -s http://localhost:8080/api/v1/dashboard/summary | jq .
```

## Makefile Targets

```
make build              Build all five binaries → dist/
make test               Run all tests (unit + integration)
make test-unit          Unit tests only (no Docker required)
make test-integration   Integration tests (requires Docker)
make test-threats       Run all 8 threat scenario tests
make lint               Run golangci-lint
make fmt                gofmt + goimports
make generate           buf generate (protos)
make migrate            goose up (runs pending migrations)
make seed               Insert default tenant + policies + rules
make docker-up          Start postgres, redis, otel-collector
make docker-down        Stop and remove containers
make docker-build       Build all Docker images
make clean              Remove dist/ and build artifacts
```

## Repository Layout

```
mcpids/
├── cmd/            Entry points (gateway, control-plane, agent, semantic-service, sensor-ebpf)
├── internal/       Private implementation packages
├── pkg/            Exported packages (types, clients, proto)
├── policies/       YAML policy files
├── tests/          Integration + unit tests + fixtures
├── deploy/         Docker Compose + Dockerfiles + k8s manifests
├── docs/           This documentation
└── scripts/        Helper shell scripts
```

## Environment Variables

The components read config from a YAML file (`--config path/to/file.yaml`), but every field can be overridden with an environment variable. The naming convention is `MCPIDS_` + the upper-cased YAML path with dots replaced by underscores.

### Gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPIDS_GATEWAY_HTTP_LISTEN_ADDR` | `:8443` | Gateway listener |
| `MCPIDS_GATEWAY_UPSTREAM_URL` | `http://localhost:3000` | MCP server to proxy |
| `MCPIDS_GATEWAY_PIPELINE_TIMEOUT_MS` | `100` | Hot-path timeout |
| `MCPIDS_GATEWAY_PIPELINE_FAIL_OPEN` | `false` | Fail-open on timeout |
| `MCPIDS_GATEWAY_PIPELINE_MONITOR_ONLY` | `false` | Never block, only emit |
| `MCPIDS_REDIS_URL` | `` | Redis URL (optional) |
| `MCPIDS_TELEMETRY_LOG_LEVEL` | `info` | debug\|info\|warn\|error |
| `MCPIDS_TELEMETRY_LOG_FORMAT` | `json` | json\|text |

### Control Plane

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPIDS_CONTROLPLANE_HTTP_LISTEN_ADDR` | `:8080` | REST API listener |
| `MCPIDS_CONTROLPLANE_GRPC_LISTEN_ADDR` | `:9090` | gRPC listener |
| `MCPIDS_DATABASE_URL` | `` | PostgreSQL DSN |
| `MCPIDS_REDIS_URL` | `` | Redis URL |

### Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPIDS_AGENT_TENANT_ID` | `default` | Tenant identifier |
| `MCPIDS_AGENT_CONTROL_PLANE_ADDR` | `localhost:9090` | gRPC control plane |
| `MCPIDS_AGENT_WRAP_STDIO` | `false` | Enable stdio wrapping |
| `MCPIDS_AGENT_HEARTBEAT_INTERVAL` | `30s` | Policy refresh interval |

## Sample Config Files

### `config/gateway.yaml` (development)

```yaml
gateway:
  http_listen_addr: ":8443"
  upstream_url: "http://localhost:3000"
  pipeline:
    timeout_ms: 100
    fail_open: false
    monitor_only: true   # safe for dev

redis:
  url: "redis://localhost:6379"

telemetry:
  service_name: "mcpids-gateway"
  log_level: "debug"
  log_format: "text"
  prometheus_addr: ":9100"
```

### `config/control-plane.yaml` (development)

```yaml
controlplane:
  http_listen_addr: ":8080"
  grpc_listen_addr: ":9090"

database:
  url: "postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable"

redis:
  url: "redis://localhost:6379"

telemetry:
  service_name: "mcpids-control-plane"
  log_level: "debug"
  log_format: "text"
```

### `config/agent.yaml` (development)

```yaml
agent:
  tenant_id: "default"
  control_plane_addr: "localhost:9090"
  wrap_stdio: false
  heartbeat_interval: 30s

discovery:
  config_paths:
    - "~/.cursor/mcp.json"
    - "~/.claude.json"

telemetry:
  service_name: "mcpids-agent"
  log_level: "debug"
  log_format: "text"
```

## Running Tests

### Unit tests (no external services needed)

```bash
make test-unit
# or directly:
go test -v ./tests/unit/... ./internal/... ./pkg/...
```

### Threat scenario tests

```bash
make test-threats
# or directly:
./scripts/run-threat-scenarios.sh
```

Expected output: all 8 scenarios listed, each with `PASS`.

### Integration tests (Docker required)

```bash
make docker-up
make migrate
make test-integration
```

Integration tests spin up a mock MCP server on an ephemeral port, start the gateway in-process, and run end-to-end assertions.

## Regenerating Protobuf Code

```bash
# Install buf if needed
go install github.com/bufbuild/buf/cmd/buf@latest

# Generate
make generate
# or directly:
buf generate pkg/proto
```

Generated files land in `pkg/proto/gen/`. Commit them alongside the `.proto` sources.

## Database Migrations

Migrations use [goose](https://github.com/pressly/goose) and live in `internal/storage/postgres/migrations/`.

```bash
# Apply all pending migrations
make migrate

# Roll back the last migration
goose -dir internal/storage/postgres/migrations postgres \
  "postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable" down

# Show migration status
goose -dir internal/storage/postgres/migrations postgres \
  "postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable" status
```

## Generating Dev TLS Certificates

```bash
./scripts/gen-certs.sh
# Creates: certs/ca.crt, certs/gateway.crt, certs/gateway.key
```

## Linting

```bash
make lint
```

The linter config is in `.golangci.yml`. Key enabled linters: `errcheck`, `govet`, `staticcheck`, `gosec`, `exhaustive`, `gofumpt`.

To auto-fix formatting issues:
```bash
make fmt
```

## Hot Reloading (Development)

The gateway and control plane watch their YAML config files and rule files for changes via the `Reload()` method. In dev mode, a SIGHUP triggers a reload:

```bash
kill -HUP $(pgrep -f mcpids-gateway)
```

Policy YAML files in `policies/` are hot-reloaded without a restart; changes take effect within one reload cycle.

## Connecting a Test MCP Server

To test the gateway with a real MCP server, run any stdio or HTTP MCP server on `localhost:3000` and start the gateway pointing at it:

```bash
# Example: start a test MCP server (replace with your server binary)
my-mcp-server --http :3000 &

# Start gateway pointing at it
./dist/mcpids-gateway --config config/gateway.yaml
```

Now connect any MCP client (Claude Desktop, Cursor, VS Code) to `http://localhost:8443` instead of the upstream server. All traffic will be intercepted and inspected.

## Observability (Local)

With the dev Docker Compose running:

- **Prometheus metrics**: `http://localhost:9100/metrics` (gateway)
- **OTel collector Prometheus**: `http://localhost:9464/metrics`
- **Traces**: exported to OTel collector on `localhost:4317`; add Jaeger or Tempo to visualize
- **Structured logs**: emitted to stdout in JSON format; pipe through `jq` for readability

```bash
./dist/mcpids-gateway --config config/gateway.yaml 2>&1 | jq .
```

## Troubleshooting

### Gateway returns 503 on all requests
Check that the upstream MCP server is running and `gateway.upstream_url` points to it. Test directly:
```bash
curl -s http://localhost:3000/healthz
```

### Redis connection refused
Ensure the backing services are running: `make docker-up`. The gateway and agent work without Redis (falls back to in-memory session state) but approvals will be unavailable.

### Migration fails: "relation already exists"
The database already has migrations applied. Run `goose status` to see current state and apply only the missing ones.

### Build errors on sensor-ebpf on macOS
The eBPF sensor requires Linux. The `sensor-ebpf` binary will compile on macOS (the Linux-specific code is behind build tags) but `IsSupported()` returns false. Run the sensor only on Linux hosts.

### `go: module lookup disabled by GONOSUMCHECK`
Set `GONOSUMCHECK=""` or add the module to your `GONOSUMCHECK` list if working in a restricted network.
