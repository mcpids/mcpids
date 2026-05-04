// Package session manages MCP session lifecycle for the gateway and agent.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mcpids/mcpids/internal/mcp"
	redisclient "github.com/mcpids/mcpids/internal/storage/redis"
)

const (
	// DefaultSessionTTL is the Redis TTL for session state.
	// Sessions that have not been seen for this duration are evicted from Redis.
	// The DB record is retained for forensics.
	DefaultSessionTTL = 24 * time.Hour
)

// Manager manages MCP session lifecycle.
// Session state is cached in Redis for fast gateway lookups and persisted to PostgreSQL.
type Manager interface {
	// Create creates a new session and stores it in Redis.
	Create(ctx context.Context, sess *mcp.Session) error

	// Get retrieves a session by internal MCPIDS session ID.
	Get(ctx context.Context, sessionID string) (*mcp.Session, error)

	// GetByExternalID retrieves a session by the MCP-Session-Id header value.
	GetByExternalID(ctx context.Context, externalID string) (*mcp.Session, error)

	// UpdateState transitions a session to the given state.
	UpdateState(ctx context.Context, sessionID string, state mcp.SessionState, reason string) error

	// Quarantine transitions a session to StateQuarantined.
	Quarantine(ctx context.Context, sessionID, reason string) error

	// Close transitions a session to StateClosed.
	Close(ctx context.Context, sessionID string) error

	// Touch updates the session's LastSeenAt timestamp.
	Touch(ctx context.Context, sessionID string) error

	// Delete removes a session from the cache (not the DB).
	Delete(ctx context.Context, sessionID string) error
}

// managerImpl is the default Manager implementation backed by Redis.
// For gateway HA deployments, all gateway instances share the same Redis,
// providing session affinity without sticky sessions.
type managerImpl struct {
	redis *redisclient.Client
	store Store
	mu    sync.RWMutex
	// local is a local in-memory map for single-instance use (agent/dev).
	// In gateway mode with Redis, this is supplementary.
	local map[string]*mcp.Session
}

// NewManager creates a session manager backed by Redis.
// Pass nil for redis to use in-memory storage only (for testing or agent use).
func NewManager(redis *redisclient.Client) Manager {
	return NewManagerWithStore(redis, nil)
}

// NewManagerWithStore creates a session manager with optional Redis cache and durable store.
func NewManagerWithStore(redis *redisclient.Client, store Store) Manager {
	return &managerImpl{
		redis: redis,
		store: store,
		local: make(map[string]*mcp.Session),
	}
}

// Create implements Manager.
func (m *managerImpl) Create(ctx context.Context, sess *mcp.Session) error {
	if sess.ID == "" {
		sess.ID = uuid.New().String()
	}
	sess.StartedAt = time.Now().UTC()
	sess.LastSeenAt = sess.StartedAt

	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session: marshal: %w", err)
	}

	// Store in local map for fast local access.
	m.mu.Lock()
	m.local[sess.ID] = sess
	m.mu.Unlock()

	// Store in Redis if available.
	if m.redis != nil {
		key := redisclient.SessionKey(sess.ID)
		if err := m.redis.SetJSON(ctx, key, data, DefaultSessionTTL); err != nil {
			slog.Warn("session: redis write failed, using local only", "error", err)
		}

		if sess.ExternalID != "" {
			extKey := redisclient.SessionExternalKey(sess.ExternalID)
			if err := m.redis.SetJSON(ctx, extKey, []byte(sess.ID), DefaultSessionTTL); err != nil {
				slog.Warn("session: redis external_id write failed", "error", err)
			}
		}
	}

	slog.Info("session: created",
		"session_id", sess.ID,
		"tenant_id", sess.TenantID,
		"transport", sess.Transport)

	m.persistSession(ctx, sess)

	return nil
}

// Get implements Manager.
func (m *managerImpl) Get(ctx context.Context, sessionID string) (*mcp.Session, error) {
	// Check local first.
	m.mu.RLock()
	if sess, ok := m.local[sessionID]; ok {
		m.mu.RUnlock()
		return sess, nil
	}
	m.mu.RUnlock()

	// Fall through to Redis.
	if m.redis != nil {
		data, err := m.redis.GetJSON(ctx, redisclient.SessionKey(sessionID))
		if err != nil {
			return nil, fmt.Errorf("session: redis get: %w", err)
		}
		if data != nil {
			var sess mcp.Session
			if err := json.Unmarshal(data, &sess); err != nil {
				return nil, fmt.Errorf("session: unmarshal: %w", err)
			}

			m.mu.Lock()
			m.local[sessionID] = &sess
			m.mu.Unlock()

			return &sess, nil
		}
	}

	if m.store != nil {
		sess, err := m.store.Load(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if sess != nil {
			m.mu.Lock()
			m.local[sessionID] = sess
			m.mu.Unlock()
		}
		return sess, nil
	}

	return nil, nil
}

// GetByExternalID implements Manager.
func (m *managerImpl) GetByExternalID(ctx context.Context, externalID string) (*mcp.Session, error) {
	// Linear scan of local map.
	m.mu.RLock()
	for _, sess := range m.local {
		if sess.ExternalID == externalID {
			m.mu.RUnlock()
			return sess, nil
		}
	}
	m.mu.RUnlock()

	// Look up the internal ID from Redis.
	if m.redis != nil {
		idData, err := m.redis.GetJSON(ctx, redisclient.SessionExternalKey(externalID))
		if err != nil {
			return nil, err
		}
		if idData != nil {
			return m.Get(ctx, string(idData))
		}
	}

	if m.store != nil {
		sess, err := m.store.LoadByExternalID(ctx, externalID)
		if err != nil {
			return nil, err
		}
		if sess != nil {
			m.mu.Lock()
			m.local[sess.ID] = sess
			m.mu.Unlock()
		}
		return sess, nil
	}

	return nil, nil
}

// UpdateState implements Manager.
func (m *managerImpl) UpdateState(ctx context.Context, sessionID string, state mcp.SessionState, reason string) error {
	sess, err := m.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return fmt.Errorf("session: not found: %s", sessionID)
	}

	sess.State = state
	sess.LastSeenAt = time.Now().UTC()
	if reason != "" {
		sess.QuarantineReason = reason
	}
	if state == mcp.StateClosed || state == mcp.StateError {
		endedAt := sess.LastSeenAt
		sess.EndedAt = &endedAt
	}

	m.mu.Lock()
	m.local[sessionID] = sess
	m.mu.Unlock()

	if m.redis != nil {
		data, _ := json.Marshal(sess)
		_ = m.redis.SetJSON(ctx, redisclient.SessionKey(sessionID), data, DefaultSessionTTL)
	}

	m.persistSession(ctx, sess)
	return nil
}

// Quarantine implements Manager.
func (m *managerImpl) Quarantine(ctx context.Context, sessionID, reason string) error {
	t := time.Now().UTC()

	sess, err := m.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return fmt.Errorf("session: not found: %s", sessionID)
	}

	sess.State = mcp.StateQuarantined
	sess.QuarantineReason = reason
	sess.QuarantinedAt = &t
	sess.LastSeenAt = t

	m.mu.Lock()
	m.local[sessionID] = sess
	m.mu.Unlock()

	if m.redis != nil {
		data, _ := json.Marshal(sess)
		_ = m.redis.SetJSON(ctx, redisclient.SessionKey(sessionID), data, DefaultSessionTTL)
	}

	slog.Warn("session: quarantined",
		"session_id", sessionID,
		"reason", reason)

	m.persistSession(ctx, sess)

	return nil
}

// Close implements Manager.
func (m *managerImpl) Close(ctx context.Context, sessionID string) error {
	return m.UpdateState(ctx, sessionID, mcp.StateClosed, "")
}

// Touch implements Manager.
func (m *managerImpl) Touch(ctx context.Context, sessionID string) error {
	var sess *mcp.Session
	m.mu.Lock()
	if current, ok := m.local[sessionID]; ok {
		current.LastSeenAt = time.Now().UTC()
		sess = current
	}
	m.mu.Unlock()
	if sess != nil {
		m.persistSession(ctx, sess)
	}
	return nil
}

// Delete implements Manager.
func (m *managerImpl) Delete(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	delete(m.local, sessionID)
	m.mu.Unlock()

	if m.redis != nil {
		_ = m.redis.Del(ctx, redisclient.SessionKey(sessionID))
	}

	return nil
}

func (m *managerImpl) persistSession(ctx context.Context, sess *mcp.Session) {
	if m.store == nil || sess == nil {
		return
	}
	if err := m.store.Save(ctx, sess); err != nil {
		slog.Warn("session: database persist failed", "session_id", sess.ID, "error", err)
	}
}
