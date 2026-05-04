-- +goose Up
-- +goose StatementBegin

-- ─── Graph Nodes ──────────────────────────────────────────────────────────────
-- Represents entities in the relationship graph:
-- agent | server | tool | resource | user | destination

CREATE TABLE graph_nodes (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID        NOT NULL REFERENCES tenants (id),
    kind         TEXT        NOT NULL, -- agent|server|tool|resource|user|destination
    label        TEXT        NOT NULL, -- human-readable identifier
    attrs        JSONB       NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, kind, label)
);

CREATE INDEX idx_graph_nodes_tenant ON graph_nodes (tenant_id, kind);

-- ─── Graph Edges ──────────────────────────────────────────────────────────────
-- Represents relationships: calls | reads | returns | connects | accesses

CREATE TABLE graph_edges (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  UUID        NOT NULL REFERENCES tenants (id),
    from_id    UUID        NOT NULL REFERENCES graph_nodes (id),
    to_id      UUID        NOT NULL REFERENCES graph_nodes (id),
    kind       TEXT        NOT NULL, -- calls|reads|returns|connects|accesses|exfiltrates_to
    weight     FLOAT       NOT NULL DEFAULT 1.0,
    session_id UUID        REFERENCES sessions (id),
    call_id    UUID        REFERENCES calls (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_graph_edges_tenant  ON graph_edges (tenant_id, kind);
CREATE INDEX idx_graph_edges_from    ON graph_edges (from_id, created_at DESC);
CREATE INDEX idx_graph_edges_to      ON graph_edges (to_id, created_at DESC);
CREATE INDEX idx_graph_edges_session ON graph_edges (session_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS graph_edges;
DROP TABLE IF EXISTS graph_nodes;
-- +goose StatementEnd
