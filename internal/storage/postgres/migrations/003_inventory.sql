-- +goose Up
-- +goose StatementBegin

-- ─── MCP Servers ──────────────────────────────────────────────────────────────

CREATE TABLE mcp_servers (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID        NOT NULL REFERENCES tenants (id),
    name         TEXT        NOT NULL,
    url          TEXT,                  -- NULL for stdio servers
    transport    TEXT        NOT NULL DEFAULT 'http', -- http|stdio|sse
    trust_score  FLOAT       NOT NULL DEFAULT 0.5,   -- 0.0 (untrusted) – 1.0 (trusted)
    status       TEXT        NOT NULL DEFAULT 'active', -- active|inactive|quarantined
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata     JSONB       NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_mcp_servers_tenant ON mcp_servers (tenant_id);
CREATE INDEX idx_mcp_servers_status ON mcp_servers (status);

-- ─── MCP Server Versions ──────────────────────────────────────────────────────
-- Each time we observe a server with different capabilities, we record a version.

CREATE TABLE mcp_server_versions (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id    UUID        NOT NULL REFERENCES mcp_servers (id),
    fingerprint  TEXT        NOT NULL, -- SHA-256 of canonical capabilities JSON
    capabilities JSONB       NOT NULL DEFAULT '{}',
    seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mcp_server_versions_server ON mcp_server_versions (server_id, seen_at DESC);

-- ─── Tools ───────────────────────────────────────────────────────────────────
-- Current known tool state per server (last observed).

CREATE TABLE tools (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id    UUID        NOT NULL REFERENCES mcp_servers (id),
    tenant_id    UUID        NOT NULL REFERENCES tenants (id),
    name         TEXT        NOT NULL,
    title        TEXT,
    description  TEXT        NOT NULL DEFAULT '',
    input_schema JSONB       NOT NULL DEFAULT '{}',
    output_schema JSONB,
    is_destructive BOOLEAN   NOT NULL DEFAULT FALSE,
    is_read_only   BOOLEAN   NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, name)
);

CREATE INDEX idx_tools_server   ON tools (server_id);
CREATE INDEX idx_tools_tenant   ON tools (tenant_id);
-- Full-text search on tool descriptions using pg_trgm
CREATE INDEX idx_tools_desc_trgm ON tools USING gin (description gin_trgm_ops);

-- ─── Tool Snapshots ───────────────────────────────────────────────────────────
-- Immutable point-in-time captures of the full tool list for a server.
-- Used by the diff engine to detect changes between snapshots.

CREATE TABLE tool_snapshots (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id   UUID        NOT NULL REFERENCES mcp_servers (id),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id),
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum    TEXT        NOT NULL, -- SHA-256 of canonical tools JSON
    payload     JSONB       NOT NULL  -- full []mcp.Tool as JSON
);

CREATE INDEX idx_tool_snapshots_server ON tool_snapshots (server_id, captured_at DESC);

-- ─── Prompts ─────────────────────────────────────────────────────────────────

CREATE TABLE prompts (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id   UUID        NOT NULL REFERENCES mcp_servers (id),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id),
    name        TEXT        NOT NULL,
    title       TEXT,
    description TEXT        NOT NULL DEFAULT '',
    arguments   JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, name)
);

CREATE INDEX idx_prompts_server ON prompts (server_id);

-- ─── Resources ───────────────────────────────────────────────────────────────

CREATE TABLE resources (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id   UUID        NOT NULL REFERENCES mcp_servers (id),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id),
    uri         TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    title       TEXT,
    description TEXT,
    mime_type   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, uri)
);

CREATE INDEX idx_resources_server ON resources (server_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS prompts;
DROP TABLE IF EXISTS tool_snapshots;
DROP TABLE IF EXISTS tools;
DROP TABLE IF EXISTS mcp_server_versions;
DROP TABLE IF EXISTS mcp_servers;
-- +goose StatementEnd
