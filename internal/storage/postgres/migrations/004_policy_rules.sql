-- +goose Up
-- +goose StatementBegin

-- ─── Policies ─────────────────────────────────────────────────────────────────
-- A policy is the top-level enforcement configuration for a tenant.
-- A tenant may have multiple policies; the one with the lowest priority number is evaluated first.

CREATE TABLE policies (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID        NOT NULL REFERENCES tenants (id),
    name             TEXT        NOT NULL,
    description      TEXT,
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    is_dry_run       BOOLEAN     NOT NULL DEFAULT FALSE, -- monitor_only mode for safe rollout
    priority         INT         NOT NULL DEFAULT 100,
    default_decision TEXT        NOT NULL DEFAULT 'allow', -- fallback when no rule matches
    settings         JSONB       NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_policies_tenant   ON policies (tenant_id);
CREATE INDEX idx_policies_active   ON policies (tenant_id, is_active, priority);

-- ─── Rules ────────────────────────────────────────────────────────────────────
-- Rules are evaluatable security assertions attached to a policy.
-- They are evaluated in priority order (lowest number = highest priority).

CREATE TABLE rules (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id),
    policy_id   UUID        REFERENCES policies (id),  -- NULL = global rule
    name        TEXT        NOT NULL,
    description TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    priority    INT         NOT NULL DEFAULT 100,
    scope       JSONB       NOT NULL DEFAULT '{}',      -- RuleScope struct
    conditions  JSONB       NOT NULL DEFAULT '[]',      -- []Condition struct
    any_of      JSONB,                                  -- [][]Condition (OR of AND groups)
    action      JSONB       NOT NULL DEFAULT '{}',      -- RuleAction struct
    severity    TEXT        NOT NULL DEFAULT 'medium',  -- info|low|medium|high|critical
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    source      TEXT        NOT NULL DEFAULT 'db',      -- db|yaml|builtin
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_tenant   ON rules (tenant_id, enabled, priority);
CREATE INDEX idx_rules_policy   ON rules (policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX idx_rules_tags     ON rules USING gin (tags);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS policies;
-- +goose StatementEnd
