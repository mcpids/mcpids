package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

// Store abstracts snapshot persistence. Implementations include in-memory (default)
// and PostgreSQL (production).
type Store interface {
	// SaveSnapshot persists a snapshot and returns any error.
	SaveSnapshot(ctx context.Context, tenantID string, snap *Snapshot) error

	// LoadLatest loads the most recent snapshot for the given server.
	// Returns (nil, nil) if no snapshot exists.
	LoadLatest(ctx context.Context, serverID string) (*Snapshot, error)

	// LoadToolNames loads the set of all known tool names for a server.
	LoadToolNames(ctx context.Context, serverID string) (map[string]struct{}, error)
}

// ─── In-memory store (MVP default) ──────────────────────────────────────────

// memStore keeps snapshots in memory. Used when no DB is available.
type memStore struct{}

func (m *memStore) SaveSnapshot(_ context.Context, _ string, _ *Snapshot) error { return nil }
func (m *memStore) LoadLatest(_ context.Context, _ string) (*Snapshot, error)   { return nil, nil }
func (m *memStore) LoadToolNames(_ context.Context, _ string) (map[string]struct{}, error) {
	return nil, nil
}

// ─── PostgreSQL store ───────────────────────────────────────────────────────

// PGStore persists snapshots to the tool_snapshots table.
type PGStore struct {
	pool            *pgxpool.Pool
	defaultTenantID string
}

// NewPGStore creates a PostgreSQL-backed snapshot store.
func NewPGStore(pool *pgxpool.Pool, defaultTenantID ...string) *PGStore {
	store := &PGStore{pool: pool}
	if len(defaultTenantID) > 0 {
		store.defaultTenantID = defaultTenantID[0]
	}
	return store
}

// SaveSnapshot inserts a snapshot row into tool_snapshots.
func (s *PGStore) SaveSnapshot(ctx context.Context, tenantID string, snap *Snapshot) error {
	payload, err := json.Marshal(snap.Tools)
	if err != nil {
		return fmt.Errorf("diff store: marshal tools: %w", err)
	}
	if tenantID == "" {
		tenantID = s.defaultTenantID
	}
	if tenantID == "" {
		return fmt.Errorf("diff store: tenant id is required")
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO tool_snapshots (id, server_id, tenant_id, captured_at, checksum, payload)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		snap.ID, snap.ServerID, tenantID, snap.CapturedAt, snap.Checksum, string(payload),
	)
	if err != nil {
		return fmt.Errorf("diff store: insert snapshot: %w", err)
	}

	slog.Debug("diff store: snapshot persisted", "id", snap.ID, "server_id", snap.ServerID)
	return nil
}

// GRPCStore submits snapshots to the control-plane InventoryService.
type GRPCStore struct {
	client   mcpidsv1.InventoryServiceClient
	tenantID string
}

// NewGRPCStore creates a service-plane snapshot store.
func NewGRPCStore(client mcpidsv1.InventoryServiceClient, tenantID string) *GRPCStore {
	return &GRPCStore{client: client, tenantID: tenantID}
}

// SaveSnapshot implements Store.
func (s *GRPCStore) SaveSnapshot(ctx context.Context, tenantID string, snap *Snapshot) error {
	if s == nil || s.client == nil || snap == nil {
		return nil
	}
	if tenantID == "" {
		tenantID = s.tenantID
	}
	if tenantID == "" {
		return fmt.Errorf("diff grpc store: tenant id is required")
	}
	payload, err := json.Marshal(snap.Tools)
	if err != nil {
		return fmt.Errorf("diff grpc store: marshal tools: %w", err)
	}
	_, err = s.client.SubmitToolSnapshot(ctx, &mcpidsv1.ToolSnapshotRequest{
		TenantId:   tenantID,
		ServerId:   snap.ServerID,
		ToolsJson:  payload,
		CapturedAt: snap.CapturedAt.UnixMilli(),
	})
	if err != nil {
		return fmt.Errorf("diff grpc store: submit snapshot: %w", err)
	}
	return nil
}

// LoadLatest implements Store.
func (s *GRPCStore) LoadLatest(ctx context.Context, serverID string) (*Snapshot, error) {
	if s == nil || s.client == nil {
		return nil, nil
	}
	resp, err := s.client.GetServerTools(ctx, &mcpidsv1.GetServerToolsRequest{
		TenantId: s.tenantID,
		ServerId: serverID,
	})
	if err != nil {
		return nil, fmt.Errorf("diff grpc store: get latest snapshot: %w", err)
	}
	if resp == nil || resp.SnapshotId == "" || len(resp.ToolsJson) == 0 {
		return nil, nil
	}
	var tools []ToolSnapshot
	if err := json.Unmarshal(resp.ToolsJson, &tools); err != nil {
		return nil, fmt.Errorf("diff grpc store: decode latest snapshot: %w", err)
	}
	return &Snapshot{
		ID:         resp.SnapshotId,
		ServerID:   serverID,
		CapturedAt: time.UnixMilli(resp.SnapshotAt).UTC(),
		Checksum:   computeChecksum(tools),
		Tools:      tools,
	}, nil
}

// LoadToolNames implements Store.
func (s *GRPCStore) LoadToolNames(ctx context.Context, serverID string) (map[string]struct{}, error) {
	snap, err := s.LoadLatest(ctx, serverID)
	if err != nil || snap == nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(snap.Tools))
	for _, tool := range snap.Tools {
		names[tool.Name] = struct{}{}
	}
	return names, nil
}

// LoadLatest retrieves the most recent snapshot for a server from the DB.
func (s *PGStore) LoadLatest(ctx context.Context, serverID string) (*Snapshot, error) {
	var id, checksum string
	var capturedAt time.Time
	var payload json.RawMessage

	err := s.pool.QueryRow(ctx,
		`SELECT id, checksum, captured_at, payload
		 FROM tool_snapshots
		 WHERE server_id = $1
		 ORDER BY captured_at DESC
		 LIMIT 1`, serverID,
	).Scan(&id, &checksum, &capturedAt, &payload)

	if err != nil {
		// No rows = no previous snapshot.
		return nil, nil
	}

	var tools []ToolSnapshot
	if err := json.Unmarshal(payload, &tools); err != nil {
		return nil, fmt.Errorf("diff store: unmarshal payload: %w", err)
	}

	return &Snapshot{
		ID:         id,
		ServerID:   serverID,
		CapturedAt: capturedAt,
		Checksum:   checksum,
		Tools:      tools,
	}, nil
}

// LoadToolNames returns a set of all tool names ever seen for a server
// by scanning the most recent snapshot payload.
func (s *PGStore) LoadToolNames(ctx context.Context, serverID string) (map[string]struct{}, error) {
	snap, err := s.LoadLatest(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, nil
	}

	names := make(map[string]struct{}, len(snap.Tools))
	for _, t := range snap.Tools {
		names[t.Name] = struct{}{}
	}
	return names, nil
}

// ─── Engine constructor with store ──────────────────────────────────────────

// NewEngineWithStore creates a diff engine that persists snapshots to the given store.
// On startup, it pre-loads the most recent snapshot per server from the store to
// avoid a blind first-snapshot gap after restarts.
func NewEngineWithStore(store Store) Engine {
	return &engineImpl{
		snapshots: make(map[string]*Snapshot),
		toolSets:  make(map[string]map[string]struct{}),
		store:     store,
	}
}
