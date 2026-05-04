-- +goose Up
-- +goose StatementBegin

-- ─── Calls ────────────────────────────────────────────────────────────────────
-- Every intercepted MCP method invocation is recorded here.
-- This is the primary forensic record.

CREATE TABLE calls (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id       UUID        NOT NULL REFERENCES sessions (id),
    tenant_id        UUID        NOT NULL REFERENCES tenants (id),
    server_id        UUID        REFERENCES mcp_servers (id),
    method           TEXT        NOT NULL, -- e.g. tools/call
    tool_name        TEXT,                 -- populated for tools/call
    request_payload  JSONB,               -- sanitized copy of the request
    response_payload JSONB,               -- sanitized copy of the response
    verdict          JSONB,               -- Verdict struct
    duration_ms      INT,
    called_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_calls_session    ON calls (session_id, called_at DESC);
CREATE INDEX idx_calls_tenant     ON calls (tenant_id, called_at DESC);
CREATE INDEX idx_calls_server     ON calls (server_id, called_at DESC);
CREATE INDEX idx_calls_tool       ON calls (tenant_id, tool_name, called_at DESC) WHERE tool_name IS NOT NULL;

-- ─── Detections ───────────────────────────────────────────────────────────────
-- A detection is created when the policy engine produces a non-allow verdict.

CREATE TABLE detections (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id          UUID        REFERENCES calls (id),
    session_id       UUID        REFERENCES sessions (id),
    tenant_id        UUID        NOT NULL REFERENCES tenants (id),
    server_id        UUID        REFERENCES mcp_servers (id),
    rule_ids         TEXT[]      NOT NULL DEFAULT '{}',
    semantic_labels  TEXT[]      NOT NULL DEFAULT '{}',
    risk_score       FLOAT       NOT NULL DEFAULT 0.0,
    severity         TEXT        NOT NULL DEFAULT 'info',
    decision         TEXT        NOT NULL DEFAULT 'monitor_only',
    evidence         JSONB       NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detections_tenant    ON detections (tenant_id, severity, created_at DESC);
CREATE INDEX idx_detections_session   ON detections (session_id, created_at DESC);
CREATE INDEX idx_detections_call      ON detections (call_id);
CREATE INDEX idx_detections_severity  ON detections (tenant_id, severity);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS detections;
DROP TABLE IF EXISTS calls;
-- +goose StatementEnd
