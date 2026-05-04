-- +goose Up
-- +goose StatementBegin

CREATE TABLE sessions (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID        NOT NULL REFERENCES tenants (id),
    agent_id          UUID        NOT NULL REFERENCES agents (id),
    mcp_server_id     UUID,       -- NULL until the server is registered
    external_id       TEXT        NOT NULL, -- MCP-Session-Id header or synthetic stdio ID
    protocol_version  TEXT        NOT NULL DEFAULT '2025-11-25',
    client_name       TEXT,
    client_version    TEXT,
    server_name       TEXT,
    server_version    TEXT,
    transport         TEXT        NOT NULL DEFAULT 'http', -- http|stdio|sse
    state             TEXT        NOT NULL DEFAULT 'initializing',
    -- States: initializing | ready | quarantined | closed | error
    quarantine_reason TEXT,
    quarantined_at    TIMESTAMPTZ,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at          TIMESTAMPTZ,
    metadata          JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_sessions_tenant    ON sessions (tenant_id);
CREATE INDEX idx_sessions_agent     ON sessions (agent_id);
CREATE INDEX idx_sessions_external  ON sessions (external_id);
CREATE INDEX idx_sessions_state     ON sessions (state);
CREATE INDEX idx_sessions_started   ON sessions (started_at DESC);
CREATE INDEX idx_sessions_server    ON sessions (mcp_server_id) WHERE mcp_server_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd
