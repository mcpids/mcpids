-- +goose Up
-- +goose StatementBegin

-- ─── Audit Events ─────────────────────────────────────────────────────────────
-- Immutable audit trail for all control-plane actions.
-- Never DELETE from this table. Retention is managed by external archival.

CREATE TABLE audit_events (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (id),
    actor_id      UUID,       -- user/agent that performed the action (NULL = system)
    actor_kind    TEXT        NOT NULL DEFAULT 'system', -- user|agent|system
    action        TEXT        NOT NULL, -- e.g. policy.created, rule.updated, approval.decided
    resource_kind TEXT,       -- e.g. policy|rule|session|incident
    resource_id   UUID,
    payload       JSONB       NOT NULL DEFAULT '{}', -- before/after for mutations
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit events are append-only; only allow reads and inserts.
-- Partitioning by month is recommended for large deployments (out of scope for MVP).

CREATE INDEX idx_audit_tenant    ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_actor     ON audit_events (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_resource  ON audit_events (resource_kind, resource_id) WHERE resource_id IS NOT NULL;
CREATE INDEX idx_audit_action    ON audit_events (action, created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_events;
-- +goose StatementEnd
