// Package postgres provides the PostgreSQL database pool and helpers.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds PostgreSQL connection parameters.
type Config struct {
	URL               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// DefaultConfig returns conservative default pool settings.
func DefaultConfig(url string) Config {
	return Config{
		URL:               url,
		MaxConns:          20,
		MinConns:          2,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
	}
}

// DB wraps a pgxpool.Pool with helpers used across MCPIDS.
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a new DB with the given configuration.
// It returns an error if the initial connection cannot be established.
func NewDB(ctx context.Context, cfg Config) (*DB, error) {
	defaults := DefaultConfig(cfg.URL)
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaults.MaxConns
	}
	if cfg.MinConns < 0 {
		cfg.MinConns = defaults.MinConns
	}
	if cfg.MaxConnLifetime <= 0 {
		cfg.MaxConnLifetime = defaults.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime <= 0 {
		cfg.MaxConnIdleTime = defaults.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod <= 0 {
		cfg.HealthCheckPeriod = defaults.HealthCheckPeriod
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.HealthCheckPeriod = cfg.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}

	// Verify connectivity.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping failed: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Pool returns the underlying pgxpool.Pool for direct query use.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// Ping checks that the database is reachable.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}
	return nil
}

// Close releases all connections in the pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Stats returns current pool statistics (for metrics).
func (db *DB) Stats() *pgxpool.Stat {
	return db.pool.Stat()
}
