-- +goose Up
-- +goose StatementBegin

-- Enable required extensions.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- fuzzy text search on tool descriptions

-- ─── Tenants ──────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       TEXT        NOT NULL,
    slug       TEXT        NOT NULL UNIQUE,
    plan       TEXT        NOT NULL DEFAULT 'free', -- free|pro|enterprise
    settings   JSONB       NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_tenants_slug ON tenants (slug) WHERE deleted_at IS NULL;

-- ─── Users ────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (id),
    email         TEXT        NOT NULL,
    name          TEXT,
    role          TEXT        NOT NULL DEFAULT 'viewer', -- admin|analyst|viewer
    external_id   TEXT,                                  -- SSO subject claim
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users (tenant_id);
CREATE INDEX idx_users_external_id ON users (external_id) WHERE external_id IS NOT NULL;

-- ─── Agents ───────────────────────────────────────────────────────────────────
-- An "agent" is any registered MCPIDS process: gateway, endpoint agent, or sensor.

CREATE TABLE agents (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id),
    name        TEXT        NOT NULL,
    kind        TEXT        NOT NULL, -- gateway|agent|sensor
    hostname    TEXT,
    ip_address  INET,
    version     TEXT,
    status      TEXT        NOT NULL DEFAULT 'offline', -- online|offline|degraded
    last_seen_at TIMESTAMPTZ,
    metadata    JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_tenant  ON agents (tenant_id);
CREATE INDEX idx_agents_status  ON agents (status);
CREATE INDEX idx_agents_kind    ON agents (kind);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS pgcrypto;
DROP EXTENSION IF EXISTS "uuid-ossp";
-- +goose StatementEnd
