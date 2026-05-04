-- +goose Up
-- +goose StatementBegin

CREATE TABLE approvals (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (id),
    session_id    UUID        REFERENCES sessions (id),
    call_id       UUID        REFERENCES calls (id),
    server_id     UUID        REFERENCES mcp_servers (id),
    agent_id      UUID        REFERENCES agents (id),
    tool_name     TEXT,
    raw_payload   BYTEA,      -- original MCP message bytes (encrypted at rest in production)
    verdict       JSONB       NOT NULL DEFAULT '{}',
    status        TEXT        NOT NULL DEFAULT 'pending', -- pending|approved|denied|expired
    expires_at    TIMESTAMPTZ NOT NULL,
    decided_by    UUID        REFERENCES users (id),
    decided_at    TIMESTAMPTZ,
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_approvals_tenant  ON approvals (tenant_id, status);
CREATE INDEX idx_approvals_expires ON approvals (expires_at) WHERE status = 'pending';
CREATE INDEX idx_approvals_session ON approvals (session_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS approvals;
-- +goose StatementEnd
