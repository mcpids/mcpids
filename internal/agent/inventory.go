package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"github.com/mcpids/mcpids/pkg/types"
)

// InventoryReporter builds and reports the local MCP server inventory to the control plane.
type InventoryReporter struct {
	tenantID  string
	agentID   string
	discoverer *Discoverer
	db         *pgxpool.Pool
	client     mcpidsv1.InventoryServiceClient
}

// NewInventoryReporter creates a reporter that discovers servers via the given Discoverer.
func NewInventoryReporter(tenantID, agentID string, discoverer *Discoverer, db *pgxpool.Pool, client mcpidsv1.InventoryServiceClient) *InventoryReporter {
	return &InventoryReporter{
		tenantID:  tenantID,
		agentID:   agentID,
		discoverer: discoverer,
		db:         db,
		client:     client,
	}
}

// Report discovers local servers and persists them to the control-plane database when configured.
// Without a DB pool it returns an ephemeral in-memory inventory and logs discoveries.
func (r *InventoryReporter) Report(ctx context.Context) ([]types.MCPServer, error) {
	entries := r.discoverer.Discover()
	if len(entries) == 0 {
		slog.Debug("agent: inventory: no local MCP servers found")
		return nil, nil
	}

	servers := make([]types.MCPServer, 0, len(entries))
	var rpcIDs map[string]string
	if r.client != nil && r.tenantID != "" {
		req := &mcpidsv1.InventoryReport{
			TenantId:   r.tenantID,
			AgentId:    r.agentID,
			ReportedAt: time.Now().UTC().UnixMilli(),
		}
		for _, entry := range entries {
			req.Servers = append(req.Servers, &mcpidsv1.DiscoveredServer{
				Name:      entry.Name,
				Transport: entry.Transport,
				Url:       entry.URL,
				Command:   entry.Command,
				Metadata: map[string]string{
					"source_file": entry.SourceFile,
				},
			})
		}
		if ack, err := r.client.ReportInventory(ctx, req); err != nil {
			slog.Warn("agent: inventory: gRPC report failed, falling back to local persistence", "error", err)
		} else if ack != nil {
			rpcIDs = ack.ServerIds
		}
	}
	for _, e := range entries {
		serverID := uuid.New().String()
		if rpcIDs != nil && rpcIDs[e.Name] != "" {
			serverID = rpcIDs[e.Name]
		}
		if r.db != nil && r.tenantID != "" {
			metadata, err := json.Marshal(map[string]any{
				"agent_id":    r.agentID,
				"source_file": e.SourceFile,
				"command":     e.Command,
			})
			if err != nil {
				return nil, fmt.Errorf("agent: inventory metadata marshal: %w", err)
			}
			err = r.db.QueryRow(ctx,
				`INSERT INTO mcp_servers (tenant_id, name, url, transport, status, metadata, last_seen_at)
				 VALUES ($1, $2, NULLIF($3, ''), $4, 'active', $5::jsonb, NOW())
				 ON CONFLICT (tenant_id, name) DO UPDATE SET
					 url = EXCLUDED.url,
					 transport = EXCLUDED.transport,
					 metadata = EXCLUDED.metadata,
					 last_seen_at = NOW()
				 RETURNING id::text`,
				r.tenantID, e.Name, e.URL, e.Transport, string(metadata),
			).Scan(&serverID)
			if err != nil {
				slog.Warn("agent: inventory: database upsert failed", "name", e.Name, "error", err)
			}
		}

		srv := types.MCPServer{
			ID:        serverID,
			TenantID:  r.tenantID,
			Name:      e.Name,
			Transport: types.Transport(e.Transport),
		}
		if e.URL != "" {
			srv.URL = e.URL
		}
		servers = append(servers, srv)

		slog.Info("agent: inventory: discovered server",
			"name", e.Name,
			"transport", e.Transport,
			"source", e.SourceFile)
	}

	return servers, nil
}
