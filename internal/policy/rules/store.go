package rules

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"github.com/mcpids/mcpids/pkg/types"
)

// Store loads persisted rules for hot reload.
type Store interface {
	// LoadRules returns all persisted rules.
	LoadRules(ctx context.Context) ([]Rule, error)
}

// PGStore reads rules from the PostgreSQL rules table.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PostgreSQL-backed rule store.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// LoadRules implements Store.
func (s *PGStore) LoadRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, tenant_id::text, name, COALESCE(description, ''), enabled, priority,
			 COALESCE(scope, '{}'::jsonb), COALESCE(conditions, '[]'::jsonb),
			 COALESCE(any_of, '[]'::jsonb), COALESCE(action, '{}'::jsonb),
			 severity, COALESCE(tags, '{}'::text[]), source
		 FROM rules
		 ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("rules store: query rules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var rule Rule
		var tenantID string
		var scopeJSON, conditionsJSON, anyOfJSON, actionJSON json.RawMessage
		var severity string
		if err := rows.Scan(
			&rule.ID,
			&tenantID,
			&rule.Name,
			&rule.Description,
			&rule.Enabled,
			&rule.Priority,
			&scopeJSON,
			&conditionsJSON,
			&anyOfJSON,
			&actionJSON,
			&severity,
			&rule.Tags,
			&rule.Source,
		); err != nil {
			return nil, fmt.Errorf("rules store: scan rule: %w", err)
		}
		if err := json.Unmarshal(scopeJSON, &rule.Scope); err != nil {
			return nil, fmt.Errorf("rules store: decode scope for %s: %w", rule.ID, err)
		}
		if err := json.Unmarshal(conditionsJSON, &rule.Conditions); err != nil {
			return nil, fmt.Errorf("rules store: decode conditions for %s: %w", rule.ID, err)
		}
		if err := json.Unmarshal(anyOfJSON, &rule.AnyOf); err != nil {
			return nil, fmt.Errorf("rules store: decode any_of for %s: %w", rule.ID, err)
		}
		if err := json.Unmarshal(actionJSON, &rule.Action); err != nil {
			return nil, fmt.Errorf("rules store: decode action for %s: %w", rule.ID, err)
		}
		if len(rule.Scope.TenantIDs) == 0 && tenantID != "" {
			rule.Scope.TenantIDs = []string{tenantID}
		}
		rule.Severity = types.Severity(severity)
		if rule.Source == "" {
			rule.Source = "db"
		}
		out = append(out, rule)
	}
	return out, nil
}

// GRPCStore loads the effective ruleset from the control plane PolicyService.
type GRPCStore struct {
	client   mcpidsv1.PolicyServiceClient
	tenantID string
}

// NewGRPCStore creates a service-plane rule store.
func NewGRPCStore(client mcpidsv1.PolicyServiceClient, tenantID string) *GRPCStore {
	return &GRPCStore{client: client, tenantID: tenantID}
}

// LoadRules implements Store.
func (s *GRPCStore) LoadRules(ctx context.Context) ([]Rule, error) {
	if s == nil || s.client == nil {
		return nil, nil
	}
	if s.tenantID == "" {
		return nil, fmt.Errorf("rules grpc store: tenant id is required")
	}
	resp, err := s.client.GetPolicy(ctx, &mcpidsv1.GetPolicyRequest{TenantId: s.tenantID})
	if err != nil {
		return nil, fmt.Errorf("rules grpc store: get policy: %w", err)
	}
	if resp == nil || resp.Snapshot == nil || len(resp.Snapshot.RulesJson) == 0 {
		return nil, nil
	}
	var out []Rule
	if err := json.Unmarshal(resp.Snapshot.RulesJson, &out); err != nil {
		return nil, fmt.Errorf("rules grpc store: decode rules: %w", err)
	}
	return out, nil
}
