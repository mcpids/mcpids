#!/usr/bin/env bash
# seed-db.sh - inserts default tenant, policies, and sample rules into the DB.
# Usage: ./scripts/seed-db.sh [postgres-dsn]
set -euo pipefail

DB_URL="${1:-postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable}"

echo "Seeding database: ${DB_URL%%@*}@..."

seed_db() {
  if command -v psql >/dev/null 2>&1; then
    psql "${DB_URL}"
    return
  fi

  if command -v docker >/dev/null 2>&1 && \
    [[ "${DB_URL}" == *"@localhost:"* ]] && \
    docker ps --format '{{.Names}}' | grep -qx 'deploy-postgres-1'; then
    echo "psql not found; seeding via deploy-postgres-1 container."
    docker exec -i deploy-postgres-1 psql -U mcpids -d mcpids
    return
  fi

  echo "psql not found and no local deploy-postgres-1 container fallback is available." >&2
  echo "Install psql or start Postgres with 'make docker-up'." >&2
  return 1
}

seed_db <<'SQL'
-- Default tenant
INSERT INTO tenants (id, name, slug, plan, settings)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Tenant',
    'default',
    'starter',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- Default admin user (development only)
INSERT INTO users (id, tenant_id, email, role)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'admin@localhost',
    'admin'
) ON CONFLICT (id) DO NOTHING;

-- Default dev gateway/agent process
INSERT INTO agents (id, tenant_id, name, kind, status, version)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'dev-gateway-agent',
    'gateway',
    'online',
    '0.1.0'
) ON CONFLICT (id) DO NOTHING;

-- Default upstream MCP server record used by configs/gateway.dev.yaml
INSERT INTO mcp_servers (id, tenant_id, name, url, transport, trust_score, status)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000001',
    'dev-upstream',
    'http://localhost:3000',
    'http',
    0.5,
    'active'
) ON CONFLICT (id) DO NOTHING;

-- Default balanced policy
INSERT INTO policies (id, tenant_id, name, description, is_active, is_dry_run, priority, default_decision)
VALUES (
    '00000000-0000-0000-0000-000000000020',
    '00000000-0000-0000-0000-000000000001',
    'Default Balanced Policy',
    'Balanced defaults: monitor suspicious, deny known-bad, HITL on changes.',
    true,
    false,
    100,
    'allow'
) ON CONFLICT (id) DO NOTHING;

SELECT 'Seed complete.' AS status;
SQL

echo "Database seeded."
