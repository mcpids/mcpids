package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mcpids/mcpids/internal/auth"
	"github.com/mcpids/mcpids/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticator_Disabled(t *testing.T) {
	// When JWKS URL is empty, auth is disabled.
	a := auth.NewAuthenticator(config.AuthConfig{})
	assert.False(t, a.IsEnabled())

	// Middleware should pass requests through without any token.
	handler := a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFromContext(r.Context())
		assert.Nil(t, claims, "claims should be nil when auth is disabled")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAuthenticator_Enabled_NoToken(t *testing.T) {
	// When JWKS URL is set, auth is enabled.
	a := auth.NewAuthenticator(config.AuthConfig{
		JWKSURL:  "https://example.com/.well-known/jwks.json",
		Issuer:   "test-issuer",
		Audience: "test-audience",
	})
	assert.True(t, a.IsEnabled())

	// Requests without a Bearer token should be rejected.
	handler := a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAuthenticator_Enabled_InvalidToken(t *testing.T) {
	a := auth.NewAuthenticator(config.AuthConfig{
		JWKSURL: "https://example.com/.well-known/jwks.json",
	})

	handler := a.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestClaimsFromContext_Nil(t *testing.T) {
	// Empty context returns nil claims.
	claims := auth.ClaimsFromContext(context.Background())
	assert.Nil(t, claims)
}

func TestClaims_HasRole(t *testing.T) {
	claims := &auth.Claims{
		Roles: []string{"admin", "viewer"},
	}

	assert.True(t, claims.HasRole("admin"))
	assert.True(t, claims.HasRole("viewer"))
	assert.False(t, claims.HasRole("editor"))
}

func TestClaims_HasAnyRole(t *testing.T) {
	claims := &auth.Claims{
		Roles: []string{"viewer"},
	}

	// Empty allowed = all roles allowed.
	assert.True(t, claims.HasAnyRole(nil))
	assert.True(t, claims.HasAnyRole([]string{}))

	// Match.
	assert.True(t, claims.HasAnyRole([]string{"admin", "viewer"}))

	// No match.
	assert.False(t, claims.HasAnyRole([]string{"admin", "editor"}))
}

func TestRequireRoles_Disabled(t *testing.T) {
	// When claims are nil (auth disabled), RequireRoles passes through.
	handler := auth.RequireRoles([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireRoles_EmptyAllowed(t *testing.T) {
	// Empty allowed roles = all roles pass.
	handler := auth.RequireRoles([]string{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
}
