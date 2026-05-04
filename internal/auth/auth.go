// Package auth provides JWT-based authentication and role-based authorization
// middleware for the MCPIDS control plane REST API and gRPC endpoints.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mcpids/mcpids/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey is the key type for storing auth claims in context.
type contextKey string

const claimsKey contextKey = "auth_claims"

// Claims represents the extracted JWT claims relevant to MCPIDS.
type Claims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`

	jwt.RegisteredClaims
}

// HasRole returns true if the claims include the given role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the claims include any of the given roles.
func (c *Claims) HasAnyRole(roles []string) bool {
	if len(roles) == 0 {
		return true // empty = all roles allowed
	}
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// ClaimsFromContext extracts the auth claims from the request context.
// Returns nil if no claims are present (e.g. auth disabled).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// contextWithClaims stores claims in a context.
func contextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// Authenticator validates JWT tokens and provides HTTP middleware.
type Authenticator struct {
	cfg          config.AuthConfig
	keyCache     *jwksCache
	enabled      bool
}

// NewAuthenticator creates an authenticator from the given auth config.
// If JWKSURL is empty, authentication is disabled and all requests pass through
// with nil claims.
func NewAuthenticator(cfg config.AuthConfig) *Authenticator {
	enabled := cfg.JWKSURL != ""
	a := &Authenticator{
		cfg:     cfg,
		enabled: enabled,
	}
	if enabled {
		a.keyCache = newJWKSCache(cfg.JWKSURL, cfg.JWKSRefreshInterval)
	}
	return a
}

// IsEnabled returns true if JWT authentication is configured.
func (a *Authenticator) IsEnabled() bool {
	return a.enabled
}

// Middleware returns an HTTP middleware that extracts and validates JWT tokens
// from the Authorization header. On success, claims are stored in the request context.
//
// When auth is disabled, all requests pass through with nil claims.
func (a *Authenticator) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.enabled {
				next.ServeHTTP(w, r)
				return
			}

			tokenStr := extractBearerToken(r)
			if tokenStr == "" {
				writeAuthError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}

			claims, err := a.validateToken(tokenStr)
			if err != nil {
				slog.Debug("auth: token validation failed", "error", err)
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			ctx := contextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRoles returns an HTTP middleware that checks the caller has one of the allowed roles.
// Must be used after the auth Middleware.
func RequireRoles(allowedRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				// Auth disabled - pass through.
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasAnyRole(allowedRoles) {
				writeAuthError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// UnaryServerInterceptor authenticates gRPC unary requests.
func (a *Authenticator) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !a.enabled || strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
			return handler(ctx, req)
		}
		claims, err := a.claimsFromGRPCContext(ctx)
		if err != nil {
			return nil, err
		}
		return handler(contextWithClaims(ctx, claims), req)
	}
}

// StreamServerInterceptor authenticates gRPC streaming requests.
func (a *Authenticator) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !a.enabled || strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
			return handler(srv, stream)
		}
		claims, err := a.claimsFromGRPCContext(stream.Context())
		if err != nil {
			return err
		}
		return handler(srv, &claimsServerStream{
			ServerStream: stream,
			ctx:          contextWithClaims(stream.Context(), claims),
		})
	}
}

// RequireRolesUnary enforces role-based authorization for gRPC unary requests.
func RequireRolesUnary(allowedRoles []string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
			return handler(ctx, req)
		}
		claims := ClaimsFromContext(ctx)
		if claims != nil && !claims.HasAnyRole(allowedRoles) {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}
		return handler(ctx, req)
	}
}

// RequireRolesStream enforces role-based authorization for gRPC streams.
func RequireRolesStream(allowedRoles []string) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
			return handler(srv, stream)
		}
		claims := ClaimsFromContext(stream.Context())
		if claims != nil && !claims.HasAnyRole(allowedRoles) {
			return status.Error(codes.PermissionDenied, "insufficient permissions")
		}
		return handler(srv, stream)
	}
}

// validateToken parses and validates a JWT token string.
func (a *Authenticator) validateToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	}
	if a.cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(a.cfg.Issuer))
	}
	if a.cfg.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(a.cfg.Audience))
	}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token missing kid header")
		}
		return a.keyCache.getKey(kid)
	}, parserOpts...)

	if err != nil {
		return nil, fmt.Errorf("auth: parse token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("auth: invalid token")
	}

	return claims, nil
}

// extractBearerToken extracts the token from the Authorization: Bearer <token> header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (a *Authenticator) claimsFromGRPCContext(ctx context.Context) (*Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing request metadata")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		values = md.Get("Authorization")
	}
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization metadata")
	}
	claims, err := a.validateToken(strings.TrimSpace(parts[1]))
	if err != nil {
		slog.Debug("auth: gRPC token validation failed", "error", err)
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	return claims, nil
}

type claimsServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *claimsServerStream) Context() context.Context {
	return s.ctx
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ─── JWKS cache ─────────────────────────────────────────────────────────────

// jwksCache fetches and caches JSON Web Key Sets from a JWKS endpoint.
type jwksCache struct {
	url             string
	refreshInterval time.Duration

	mu       sync.RWMutex
	keys     map[string]any
	fetchedAt time.Time
}

func newJWKSCache(url string, refreshInterval time.Duration) *jwksCache {
	if refreshInterval <= 0 {
		refreshInterval = 5 * time.Minute
	}
	return &jwksCache{
		url:             url,
		refreshInterval: refreshInterval,
		keys:            make(map[string]any),
	}
}

// getKey returns the public key for the given key ID.
// It refreshes the cache if needed.
func (c *jwksCache) getKey(kid string) (any, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.fetchedAt) > c.refreshInterval
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Cache miss or stale - refresh.
	if err := c.refresh(); err != nil {
		// If we have a cached key, use it even if stale.
		if ok {
			slog.Warn("auth: JWKS refresh failed, using cached key", "kid", kid, "error", err)
			return key, nil
		}
		return nil, fmt.Errorf("auth: JWKS fetch failed: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("auth: key %q not found in JWKS", kid)
	}
	return key, nil
}

// refresh fetches the JWKS from the configured URL and updates the cache.
func (c *jwksCache) refresh() error {
	req, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("auth: build JWKS request: %w", err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("auth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: fetch JWKS: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("auth: read JWKS body: %w", err)
	}

	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("auth: parse JWKS: %w", err)
	}

	keys := make(map[string]any, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.KID == "" {
			continue
		}
		switch strings.ToUpper(key.Kty) {
		case "RSA":
			pub, err := parseRSAJWK(key.N, key.E)
			if err != nil {
				slog.Warn("auth: skipping invalid RSA JWK", "kid", key.KID, "error", err)
				continue
			}
			keys[key.KID] = pub
		case "EC":
			pub, err := parseECJWK(key.Crv, key.X, key.Y)
			if err != nil {
				slog.Warn("auth: skipping invalid EC JWK", "kid", key.KID, "error", err)
				continue
			}
			keys[key.KID] = pub
		}
	}

	if len(keys) == 0 {
		return errors.New("auth: JWKS contains no usable signing keys")
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	slog.Debug("auth: JWKS refresh complete", "url", c.url, "keys", len(keys))
	return nil
}

func parseRSAJWK(nRaw, eRaw string) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(nRaw)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(eRaw)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}, nil
}

func parseECJWK(curveName, xRaw, yRaw string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", curveName)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xRaw)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yRaw)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
