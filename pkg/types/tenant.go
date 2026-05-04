package types

import "time"

// Plan identifies the tenant's subscription tier.
type Plan string

const (
	PlanFree       Plan = "free"
	PlanPro        Plan = "pro"
	PlanEnterprise Plan = "enterprise"
)

// Tenant is the top-level isolation boundary. Every resource belongs to a tenant.
type Tenant struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	Plan      Plan       `json:"plan"`
	Settings  JSONObject `json:"settings,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Role controls what a user can do within the admin API.
type Role string

const (
	RoleAdmin   Role = "admin"   // full CRUD on policies, can approve/deny
	RoleAnalyst Role = "analyst" // read + create incidents, can approve/deny
	RoleViewer  Role = "viewer"  // read-only
)

// User is an authenticated human principal accessing the control-plane admin API.
type User struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name,omitempty"`
	Role        Role       `json:"role"`
	ExternalID  string     `json:"external_id,omitempty"` // SSO subject claim
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AgentKind identifies the type of registered agent.
type AgentKind string

const (
	AgentKindGateway AgentKind = "gateway"
	AgentKindAgent   AgentKind = "agent"
	AgentKindSensor  AgentKind = "sensor"
)

// AgentStatus reflects the last known liveness state.
type AgentStatus string

const (
	AgentStatusOnline   AgentStatus = "online"
	AgentStatusOffline  AgentStatus = "offline"
	AgentStatusDegraded AgentStatus = "degraded"
)

// Agent is a registered gateway, endpoint agent, or sensor instance.
type Agent struct {
	ID         string      `json:"id"`
	TenantID   string      `json:"tenant_id"`
	Name       string      `json:"name"`
	Kind       AgentKind   `json:"kind"`
	Hostname   string      `json:"hostname,omitempty"`
	IPAddress  string      `json:"ip_address,omitempty"`
	Version    string      `json:"version,omitempty"`
	Status     AgentStatus `json:"status"`
	LastSeenAt *time.Time  `json:"last_seen_at,omitempty"`
	Metadata   JSONObject  `json:"metadata,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
}
