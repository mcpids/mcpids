# Deployment Guide

## Overview

MCPIDS ships five binaries, each deployable as a container or native process:

| Component | Binary | Ports | Dependencies |
|-----------|--------|-------|-------------|
| Gateway | `mcpids-gateway` | 8443 (HTTPS) | Redis (optional), Control Plane |
| Control Plane | `mcpids-control-plane` | 8080 (REST), 9090 (gRPC) | PostgreSQL, Redis |
| Agent | `mcpids-agent` | - (client only) | Redis (optional), Control Plane |
| Semantic Service | `mcpids-semantic-service` | 8091 (HTTP) | Optional external classifier backend |
| eBPF Sensor | `mcpids-sensor-ebpf` | - | Linux ≥ 5.8, CAP_BPF |

---

## Docker Compose (Recommended for Self-Hosted)

### Start the full stack

```bash
# Production stack
docker compose -f deploy/docker-compose.yml up -d

# Development stack (monitor-only, debug logging)
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.dev.yml up -d
```

### Run migrations after first start

```bash
docker compose exec control-plane \
  goose -dir /migrations postgres "$DATABASE_URL" up
```

### Environment configuration

Copy and edit the `.env` file before starting:

```bash
cp deploy/.env.example deploy/.env
```

Key variables:

```env
# PostgreSQL
POSTGRES_DB=mcpids
POSTGRES_USER=mcpids
POSTGRES_PASSWORD=<strong-password>
DATABASE_URL=postgres://mcpids:<password>@postgres:5432/mcpids?sslmode=require

# Redis
REDIS_URL=redis://:password@redis:6379

# Gateway
GATEWAY_UPSTREAM_URL=http://your-mcp-server:3000
GATEWAY_PIPELINE_MONITOR_ONLY=false

# Control Plane
CONTROLPLANE_HTTP_LISTEN_ADDR=:8080
CONTROLPLANE_GRPC_LISTEN_ADDR=:9090

# TLS
GATEWAY_TLS_CERT=/certs/gateway.crt
GATEWAY_TLS_KEY=/certs/gateway.key
```

---

## Kubernetes

Manifests are in `deploy/k8s/`. Edit `deploy/k8s/secrets.yaml` first and replace the placeholder database password, JWKS issuer/audience, gRPC bearer token, mTLS certificate/key PEMs, and semantic backend token, then apply in order:

```bash
# Namespace
kubectl apply -f deploy/k8s/namespace.yaml

# Secrets and config
kubectl apply -f deploy/k8s/secrets.yaml
kubectl apply -f deploy/k8s/configmaps.yaml

# Storage services
kubectl apply -f deploy/k8s/data-services.yaml

# Wait for storage to be ready
kubectl -n mcpids rollout status deployment/mcpids-postgres
kubectl -n mcpids rollout status deployment/mcpids-redis

# Run migrations from a local checkout against the in-cluster Postgres service
kubectl -n mcpids port-forward svc/mcpids-postgres 5432:5432 &
DB_URL='postgres://mcpids:<password>@127.0.0.1:5432/mcpids?sslmode=disable' make migrate

# Control plane and semantic service first (gateway depends on both)
kubectl apply -f deploy/k8s/control-plane.yaml
kubectl apply -f deploy/k8s/semantic-service.yaml
kubectl -n mcpids rollout status deployment/mcpids-control-plane
kubectl -n mcpids rollout status deployment/mcpids-semantic-service

# Gateway, agent, and eBPF sensor
kubectl apply -f deploy/k8s/gateway.yaml
kubectl apply -f deploy/k8s/agent.yaml
kubectl apply -f deploy/k8s/sensor-ebpf.yaml
kubectl -n mcpids rollout status deployment/mcpids-gateway
kubectl -n mcpids rollout status deployment/mcpids-agent
kubectl -n mcpids rollout status daemonset/mcpids-sensor-ebpf
```

### Horizontal scaling

The gateway and control plane are stateless and can be scaled horizontally:

```bash
kubectl -n mcpids scale deployment/mcpids-gateway --replicas=3
kubectl -n mcpids scale deployment/mcpids-control-plane --replicas=2
```

Session state is stored in Redis so all replicas share the same view.

### Resource recommendations

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|-------------|
| Gateway | 100m | 2000m | 64Mi | 512Mi |
| Control Plane | 200m | 2000m | 128Mi | 1Gi |
| Agent | 50m | 500m | 32Mi | 256Mi |
| Semantic Service | 100m | 1000m | 64Mi | 512Mi |
| eBPF Sensor | 100m | 1000m | 64Mi | 512Mi |

---

## TLS Configuration

### Gateway TLS termination

The gateway terminates TLS for MCP clients. Generate production certificates using your CA or Let's Encrypt:

```bash
# Self-signed (dev only)
./scripts/gen-certs.sh

# Let's Encrypt (production, requires public DNS)
certbot certonly --standalone -d mcp-gateway.example.com
```

Configure in `gateway.yaml`:

```yaml
gateway:
  tls:
    cert_file: "/certs/fullchain.pem"
    key_file: "/certs/privkey.pem"
    min_version: "TLS1.2"
    cipher_suites:
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

### mTLS for internal services (Gateway → Control Plane)

```yaml
# In the gateway ConfigMap
controlplane:
  grpc_addr: "control-plane.mcpids.svc:9090"
  tls:
    ca_file: "/certs/ca.crt"
    cert_file: "/certs/gateway-client.crt"
    key_file: "/certs/gateway-client.key"
```

```yaml
# In the control-plane ConfigMap
grpc:
  tls:
    ca_file: "/certs/ca.crt"
    cert_file: "/certs/control-plane.crt"
    key_file: "/certs/control-plane.key"
    require_client_cert: true
```

---

## Database

### PostgreSQL requirements

- Version: 16+
- Extensions required: `uuid-ossp`, `pg_trgm` (installed by migration 001)
- Minimum storage: 10 GiB for audit trail (grows with call volume)
- Recommended: connection pooler (PgBouncer) in front of PostgreSQL for high traffic

### Connection pool sizing

```yaml
database:
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 15m
```

Rule of thumb: `max_open_conns = num_CPU_cores * 4`, not exceeding `max_connections` in `postgresql.conf`.

### Backup strategy

Audit tables (`calls`, `detections`, `audit_events`) are append-only and grow continuously. Recommended backup approach:

1. Daily `pg_dump` of the entire database
2. WAL archiving to S3 for point-in-time recovery
3. Partition `calls` and `audit_events` by month for efficient purging

---

## Redis

### Requirements

- Version: 7+
- Persistence: AOF or RDB (session state must survive Redis restarts)
- Memory: 512 MiB minimum; approval hold channels are short-lived

### High availability

Use Redis Sentinel or Redis Cluster for production. Update the URL:

```yaml
redis:
  url: "redis-sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster"
```

---

## Observability Stack

### Metrics (Prometheus)

Each component exposes metrics on its configured `prometheus_addr`.

```yaml
telemetry:
  prometheus_addr: ":9100"
```

Add to your Prometheus `scrape_configs`:

```yaml
- job_name: mcpids-gateway
  static_configs:
    - targets: ["mcpids-gateway.mcpids.svc.cluster.local:9464"]
- job_name: mcpids-control-plane
  static_configs:
    - targets: ["mcpids-control-plane.mcpids.svc.cluster.local:9465"]
```

Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `mcpids_gateway_requests_total` | Counter | Requests by method, verdict, tenant |
| `mcpids_gateway_pipeline_duration_seconds` | Histogram | Hot-path latency |
| `mcpids_verdict_decisions_total` | Counter | Decisions by decision type |
| `mcpids_approvals_pending` | Gauge | Currently pending approvals |
| `mcpids_sessions_active` | Gauge | Active MCP sessions |
| `mcpids_detections_total` | Counter | Detections by severity |

### Traces (OpenTelemetry)

Set `OTLP_ENDPOINT` to your collector:

```yaml
telemetry:
  otlp_endpoint: "otel-collector:4317"
```

Traces flow: `Gateway → Control Plane` with propagated `trace_id`. Spans include:
- `mcpids.gateway.pipeline` - full pipeline span with verdict attribute
- `mcpids.rules.evaluate` - rules engine evaluation
- `mcpids.policy.decide` - policy decision

### Alerting (example Prometheus rules)

```yaml
groups:
  - name: mcpids
    rules:
      - alert: HighDenyRate
        expr: rate(mcpids_verdict_decisions_total{decision="deny"}[5m]) > 10
        for: 2m
        labels:
          severity: warning

      - alert: PipelineLatencyHigh
        expr: histogram_quantile(0.99, mcpids_gateway_pipeline_duration_seconds) > 0.1
        for: 5m
        labels:
          severity: warning

      - alert: ApprovalBacklog
        expr: mcpids_approvals_pending > 50
        for: 10m
        labels:
          severity: critical
```

---

## Security Hardening

### Network policy (Kubernetes)

Allow only required traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcpids-gateway
spec:
  podSelector:
    matchLabels:
      app: mcpids-gateway
  ingress:
    - ports: [{port: 8443}]      # MCP clients
  egress:
    - ports: [{port: 9090}]      # Control plane gRPC
    - ports: [{port: 6379}]      # Redis
    - ports: [{port: 3000}]      # Upstream MCP server
```

### Secrets management

Never store secrets in YAML config files. Use:
- **Kubernetes Secrets** (base) + Sealed Secrets or External Secrets Operator (recommended)
- **HashiCorp Vault** agent sidecar injection
- **AWS Secrets Manager** / GCP Secret Manager via the secrets store CSI driver

### Non-root containers

Gateway, control-plane, agent, and semantic-service images use `gcr.io/distroless/static-debian12:nonroot` and run as `nonroot`. The eBPF sensor image is Debian-based because it ships a compiled BPF object and requires kernel-facing runtime support.

### eBPF Sensor privileges

The sensor requires elevated privileges. Run with a dedicated service account:

```yaml
securityContext:
  capabilities:
    add: ["CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN"]
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
```

Never run with `privileged: true` in production - use the minimal capability set above.

---

## Upgrade Procedure

1. **Back up the database** before any upgrade
2. Deploy new control-plane version first (backwards-compatible gRPC API)
3. Run `goose up` for any new migrations
4. Roll out gateway and agent updates
5. Verify `/healthz` and `/readyz` on all components
6. Monitor for errors in logs and metrics for 15 minutes

MCPIDS follows semver. Minor versions (1.x) are backwards compatible. Major versions may require migration steps documented in `CHANGELOG.md`.

---

## Rollback

```bash
# Roll back the last migration
goose -dir internal/storage/postgres/migrations postgres "$DATABASE_URL" down

# Re-deploy previous image tags
kubectl -n mcpids set image deployment/mcpids-gateway \
  gateway=ghcr.io/mcpids/mcpids-gateway:v0.1.0
kubectl -n mcpids rollout undo deployment/mcpids-gateway
```

---

## Production Checklist

- [ ] TLS certificates installed and auto-renewal configured
- [ ] Database backups verified and tested
- [ ] Redis persistence enabled (AOF recommended)
- [ ] Prometheus scraping all components
- [ ] Alerting rules configured for deny rate, latency, and approval backlog
- [ ] `pipeline.fail_open` is `false` (fail-closed)
- [ ] `pipeline.monitor_only` is `false` (enforcement active)
- [ ] Webhook notifier configured for approval notifications
- [ ] mTLS between gateway and control plane enabled
- [ ] Non-root containers verified (`kubectl exec` should fail)
- [ ] Network policies applied
- [ ] Secrets managed via vault / secrets store (not plaintext YAML)
- [ ] Resource limits set on all deployments
- [ ] eBPF sensor deployed on Linux nodes (if required)
