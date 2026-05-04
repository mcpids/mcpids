-- +goose Up
-- +goose StatementBegin

ALTER TABLE graph_nodes
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS call_count INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_graph_nodes_last_seen ON graph_nodes (tenant_id, last_seen_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_graph_nodes_last_seen;
ALTER TABLE graph_nodes
    DROP COLUMN IF EXISTS call_count,
    DROP COLUMN IF EXISTS last_seen_at;

-- +goose StatementEnd
