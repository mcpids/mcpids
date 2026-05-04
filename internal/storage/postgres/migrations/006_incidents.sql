-- +goose Up
-- +goose StatementBegin

CREATE TABLE incidents (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID        NOT NULL REFERENCES tenants (id),
    title          TEXT        NOT NULL,
    description    TEXT,
    severity       TEXT        NOT NULL DEFAULT 'medium',
    status         TEXT        NOT NULL DEFAULT 'open', -- open|investigating|resolved|false_positive
    detection_ids  UUID[]      NOT NULL DEFAULT '{}',
    session_ids    UUID[]      NOT NULL DEFAULT '{}',
    server_ids     UUID[]      NOT NULL DEFAULT '{}',
    assigned_to    UUID        REFERENCES users (id),
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at    TIMESTAMPTZ
);

CREATE INDEX idx_incidents_tenant   ON incidents (tenant_id, status, created_at DESC);
CREATE INDEX idx_incidents_severity ON incidents (tenant_id, severity);
CREATE INDEX idx_incidents_assigned ON incidents (assigned_to) WHERE assigned_to IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS incidents;
-- +goose StatementEnd
