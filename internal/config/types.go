// Package config provides typed configuration structs for all MCPIDS components.
package config

import "time"

// GatewayConfig is the configuration for the gateway component.
type GatewayConfig struct {
	// ListenAddr is the address to listen on for incoming MCP connections.
	// Default: ":8443"
	ListenAddr string `mapstructure:"listen_addr" yaml:"listen_addr"`

	// UpstreamURL is the URL of the upstream MCP server to proxy to.
	// Required for HTTP gateway mode.
	UpstreamURL string `mapstructure:"upstream_url" yaml:"upstream_url"`

	// TenantID identifies which tenant this gateway instance serves.
	TenantID string `mapstructure:"tenant_id" yaml:"tenant_id"`

	// AgentID identifies this gateway instance as a registered agent.
	AgentID string `mapstructure:"agent_id" yaml:"agent_id"`

	// ServerID is the registered MCP server UUID for the upstream.
	// Used for diff tracking and policy scoping.
	ServerID string `mapstructure:"server_id" yaml:"server_id"`

	// TLS holds TLS termination configuration.
	TLS TLSConfig `mapstructure:"tls" yaml:"tls"`

	// ControlPlane holds the gRPC endpoint for the control plane.
	ControlPlane ControlPlaneClientConfig `mapstructure:"control_plane" yaml:"control_plane"`

	// Redis holds Redis connection configuration.
	Redis RedisConfig `mapstructure:"redis" yaml:"redis"`

	// Database optionally enables direct PostgreSQL persistence for sessions, diffs, and approvals.
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// Pipeline holds pipeline behavior configuration.
	Pipeline PipelineConfig `mapstructure:"pipeline" yaml:"pipeline"`

	// Semantic configures the semantic classifier backend.
	Semantic SemanticConfig `mapstructure:"semantic" yaml:"semantic"`

	// Rules holds rule loading configuration.
	Rules RulesConfig `mapstructure:"rules" yaml:"rules"`

	// Approvals holds HITL approval configuration.
	Approvals ApprovalsConfig `mapstructure:"approvals" yaml:"approvals"`

	// Telemetry holds observability configuration.
	Telemetry TelemetryConfig `mapstructure:"telemetry" yaml:"telemetry"`

	// Auth holds authentication configuration.
	Auth AuthConfig `mapstructure:"auth" yaml:"auth"`

	// MaxMessageSize is the maximum JSON-RPC message size in bytes.
	// Default: 4194304 (4 MiB)
	MaxMessageSize int `mapstructure:"max_message_size" yaml:"max_message_size"`
}

// ControlPlaneConfig is the configuration for the control-plane component.
type ControlPlaneConfig struct {
	// GRPCListenAddr is the gRPC server listen address.
	// Default: ":9090"
	GRPCListenAddr string `mapstructure:"grpc_listen_addr" yaml:"grpc_listen_addr"`

	// HTTPListenAddr is the REST API server listen address.
	// Default: ":8080"
	HTTPListenAddr string `mapstructure:"http_listen_addr" yaml:"http_listen_addr"`

	// Database holds PostgreSQL connection configuration.
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// Redis holds Redis connection configuration.
	Redis RedisConfig `mapstructure:"redis" yaml:"redis"`

	// TLS holds optional TLS for gRPC server.
	TLS TLSConfig `mapstructure:"tls" yaml:"tls"`

	// Auth holds authentication configuration.
	Auth AuthConfig `mapstructure:"auth" yaml:"auth"`

	// Telemetry holds observability configuration.
	Telemetry TelemetryConfig `mapstructure:"telemetry" yaml:"telemetry"`

	// Semantic configures the semantic classifier backend.
	Semantic SemanticConfig `mapstructure:"semantic" yaml:"semantic"`

	// Rules holds rule loading configuration.
	Rules RulesConfig `mapstructure:"rules" yaml:"rules"`

	// Approvals holds HITL approval configuration.
	Approvals ApprovalsConfig `mapstructure:"approvals" yaml:"approvals"`
}

// AgentConfig is the configuration for the endpoint agent component.
type AgentConfig struct {
	// TenantID is the tenant this agent belongs to.
	TenantID string `mapstructure:"tenant_id" yaml:"tenant_id"`

	// AgentID is the registered agent UUID. If empty, the agent will register on startup.
	AgentID string `mapstructure:"agent_id" yaml:"agent_id"`

	// AgentName is the human-readable name for this agent.
	AgentName string `mapstructure:"agent_name" yaml:"agent_name"`

	// ControlPlane holds the gRPC endpoint for the control plane.
	ControlPlane ControlPlaneClientConfig `mapstructure:"control_plane" yaml:"control_plane"`

	// Database optionally enables direct PostgreSQL persistence for inventory, sessions, and audit events.
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// Redis holds Redis connection configuration.
	Redis RedisConfig `mapstructure:"redis" yaml:"redis"`

	// Discovery holds local MCP server discovery configuration.
	Discovery DiscoveryConfig `mapstructure:"discovery" yaml:"discovery"`

	// Wrapper holds stdio wrapper mode configuration.
	Wrapper WrapperConfig `mapstructure:"wrapper" yaml:"wrapper"`

	// PolicyRefreshInterval controls how often the agent polls for policy updates.
	// Default: 30s
	PolicyRefreshInterval time.Duration `mapstructure:"policy_refresh_interval" yaml:"policy_refresh_interval"`

	// Telemetry holds observability configuration.
	Telemetry TelemetryConfig `mapstructure:"telemetry" yaml:"telemetry"`

	// Semantic configures the semantic classifier backend.
	Semantic SemanticConfig `mapstructure:"semantic" yaml:"semantic"`
}

// SensorConfig is the configuration for the eBPF sensor component.
type SensorConfig struct {
	// TenantID is the tenant this sensor reports to.
	TenantID string `mapstructure:"tenant_id" yaml:"tenant_id"`

	// AgentID is the registered sensor agent UUID.
	AgentID string `mapstructure:"agent_id" yaml:"agent_id"`

	// ControlPlane holds the gRPC endpoint for the control plane.
	ControlPlane ControlPlaneClientConfig `mapstructure:"control_plane" yaml:"control_plane"`

	// Database optionally enables direct PostgreSQL persistence for sensor audit events.
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// eBPF holds eBPF-specific configuration.
	EBPF EBPFConfig `mapstructure:"ebpf" yaml:"ebpf"`

	// Telemetry holds observability configuration.
	Telemetry TelemetryConfig `mapstructure:"telemetry" yaml:"telemetry"`
}

// ─── Sub-configs ──────────────────────────────────────────────────────────────

// DatabaseConfig holds PostgreSQL connection parameters.
type DatabaseConfig struct {
	URL             string        `mapstructure:"url" yaml:"url"`
	MaxConns        int32         `mapstructure:"max_conns" yaml:"max_conns"`
	MinConns        int32         `mapstructure:"min_conns" yaml:"min_conns"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime" yaml:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time" yaml:"max_conn_idle_time"`
}

// RedisConfig holds Redis connection parameters.
type RedisConfig struct {
	URL          string        `mapstructure:"url" yaml:"url"`
	PoolSize     int           `mapstructure:"pool_size" yaml:"pool_size"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" yaml:"write_timeout"`
}

// TLSConfig holds TLS certificate and key configuration.
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	CAFile   string `mapstructure:"ca_file" yaml:"ca_file"`     // for mTLS client verification
	MTLSMode string `mapstructure:"mtls_mode" yaml:"mtls_mode"` // disabled|optional|required
}

// ControlPlaneClientConfig holds the gRPC client config for connecting to the control plane.
type ControlPlaneClientConfig struct {
	Address     string        `mapstructure:"address" yaml:"address"`
	TLS         TLSConfig     `mapstructure:"tls" yaml:"tls"`
	Timeout     time.Duration `mapstructure:"timeout" yaml:"timeout"`
	Insecure    bool          `mapstructure:"insecure" yaml:"insecure"` // dev only
	BearerToken string        `mapstructure:"bearer_token" yaml:"bearer_token"`
}

// AuthConfig holds JWT/mTLS authentication configuration.
type AuthConfig struct {
	// JWKSURL is the URL to fetch the public key set for JWT verification.
	JWKSURL string `mapstructure:"jwks_url" yaml:"jwks_url"`

	// JWKSRefreshInterval controls how often the JWKS key set is refreshed.
	// Default: 5m
	JWKSRefreshInterval time.Duration `mapstructure:"jwks_refresh_interval" yaml:"jwks_refresh_interval"`

	// Issuer is the expected JWT issuer claim.
	Issuer string `mapstructure:"issuer" yaml:"issuer"`

	// Audience is the expected JWT audience claim.
	Audience string `mapstructure:"audience" yaml:"audience"`

	// AllowedRoles lists roles allowed to call admin APIs. Empty = all roles allowed.
	AllowedRoles []string `mapstructure:"allowed_roles" yaml:"allowed_roles"`
}

// TelemetryConfig holds observability configuration.
type TelemetryConfig struct {
	// ServiceName is the service name tag for all telemetry signals.
	ServiceName string `mapstructure:"service_name" yaml:"service_name"`

	// OTLPEndpoint is the gRPC endpoint for the OpenTelemetry Collector.
	// If empty, trace export is disabled.
	OTLPEndpoint string `mapstructure:"otlp_endpoint" yaml:"otlp_endpoint"`

	// PrometheusAddr is the address to expose the /metrics endpoint.
	// Default: ":9464"
	PrometheusAddr string `mapstructure:"prometheus_addr" yaml:"prometheus_addr"`

	// LogLevel sets the minimum log severity: debug|info|warn|error
	LogLevel string `mapstructure:"log_level" yaml:"log_level"`

	// LogFormat sets the log output format: json|text
	LogFormat string `mapstructure:"log_format" yaml:"log_format"`
}

// PipelineConfig controls gateway pipeline behavior.
type PipelineConfig struct {
	// MaxEvalDuration is the maximum time allowed for the full interceptor pipeline.
	// Default: 100ms
	MaxEvalDuration time.Duration `mapstructure:"max_eval_duration" yaml:"max_eval_duration"`

	// FailOpen controls fail behavior on pipeline timeout.
	// true = allow on timeout (fail-open), false = deny on timeout (fail-closed, default).
	FailOpen bool `mapstructure:"fail_open" yaml:"fail_open"`

	// MonitorOnlyMode sets the global mode override to monitor_only.
	// When true, no requests are blocked regardless of policy.
	MonitorOnlyMode bool `mapstructure:"monitor_only_mode" yaml:"monitor_only_mode"`

	// SemanticEnabled controls whether semantic classification runs.
	// Default: true (but the stub requires no external service).
	SemanticEnabled bool `mapstructure:"semantic_enabled" yaml:"semantic_enabled"`
}

// SemanticConfig selects and configures the classifier backend.
type SemanticConfig struct {
	// Provider selects the backend implementation: stub|http.
	Provider string `mapstructure:"provider" yaml:"provider"`

	// Endpoint is the HTTP classifier endpoint when provider=http.
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// BearerToken is sent as Authorization: Bearer <token> to HTTP classifier backends.
	BearerToken string `mapstructure:"bearer_token" yaml:"bearer_token"`

	// Model is forwarded to HTTP classifier backends for model routing.
	Model string `mapstructure:"model" yaml:"model"`

	// Timeout bounds each backend classification call.
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// FallbackToStub falls back to the local stub when provider=http is unhealthy.
	FallbackToStub bool `mapstructure:"fallback_to_stub" yaml:"fallback_to_stub"`
}

// RulesConfig holds rule loading configuration.
type RulesConfig struct {
	// YAMLPaths is a list of YAML rule definition files to load on startup.
	// YAML rules shadow DB rules with the same ID.
	YAMLPaths []string `mapstructure:"yaml_paths" yaml:"yaml_paths"`

	// ReloadInterval controls how often rules are reloaded from DB.
	// Default: 60s
	ReloadInterval time.Duration `mapstructure:"reload_interval" yaml:"reload_interval"`
}

// ApprovalsConfig holds HITL approval configuration.
type ApprovalsConfig struct {
	// DefaultTimeout is the default approval window before auto-expiry.
	// Default: 5m
	DefaultTimeout time.Duration `mapstructure:"default_timeout" yaml:"default_timeout"`

	// WebhookURL is an optional webhook to call when an approval is created.
	WebhookURL string `mapstructure:"webhook_url" yaml:"webhook_url"`

	// WebhookSecret is used to sign webhook payloads (HMAC-SHA256).
	WebhookSecret string `mapstructure:"webhook_secret" yaml:"webhook_secret"`
}

// DiscoveryConfig holds local MCP server discovery configuration.
type DiscoveryConfig struct {
	// ConfigPaths is a list of paths to inspect for MCP server definitions.
	// Default: ["~/.cursor/mcp.json", "~/.claude.json", "~/.config/claude/claude_desktop_config.json"]
	ConfigPaths []string `mapstructure:"config_paths" yaml:"config_paths"`

	// ScanInterval controls how often the agent re-scans config paths.
	// Default: 30s
	ScanInterval time.Duration `mapstructure:"scan_interval" yaml:"scan_interval"`
}

// WrapperConfig holds stdio process wrapper configuration.
type WrapperConfig struct {
	// Enabled controls whether the agent launches stdio MCP processes in wrapper mode.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// MaxProcesses is the maximum number of wrapped stdio processes.
	// Default: 10
	MaxProcesses int `mapstructure:"max_processes" yaml:"max_processes"`
}

// EBPFConfig holds eBPF sensor configuration.
type EBPFConfig struct {
	// Enabled controls whether eBPF programs are loaded.
	// Set to false on systems that don't support eBPF (e.g. macOS).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// ProgramsDir is the directory containing compiled eBPF object files.
	ProgramsDir string `mapstructure:"programs_dir" yaml:"programs_dir"`

	// AttachKprobes controls whether kprobe-based attach points are enabled.
	AttachKprobes bool `mapstructure:"attach_kprobes" yaml:"attach_kprobes"`

	// AttachUprobes controls whether uprobe-based TLS plaintext hooks are enabled.
	AttachUprobes bool `mapstructure:"attach_uprobes" yaml:"attach_uprobes"`

	// EventBufferSize is the capacity of the in-memory sensor event queue.
	// Default: 1024
	EventBufferSize int `mapstructure:"event_buffer_size" yaml:"event_buffer_size"`
}
