package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidationError collects multiple validation failures.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

// HasErrors returns true if any validation errors were recorded.
func (e *ValidationError) HasErrors() bool {
	return len(e.Errors) > 0
}

func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
}

// ValidateGatewayConfig checks all required fields and value constraints for GatewayConfig.
func ValidateGatewayConfig(cfg GatewayConfig) error {
	ve := &ValidationError{}

	// Listen address.
	validateAddr(ve, "listen_addr", cfg.ListenAddr)
	if strings.TrimSpace(cfg.TenantID) == "" {
		ve.add("tenant_id must not be empty")
	}
	if strings.TrimSpace(cfg.AgentID) == "" {
		ve.add("agent_id must not be empty")
	}
	if strings.TrimSpace(cfg.ServerID) == "" {
		ve.add("server_id must not be empty")
	}

	// Pipeline.
	if cfg.Pipeline.MaxEvalDuration <= 0 {
		ve.add("pipeline.max_eval_duration must be > 0")
	}

	// TLS consistency.
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" {
			ve.add("tls.cert_file is required when TLS is enabled")
		}
		if cfg.TLS.KeyFile == "" {
			ve.add("tls.key_file is required when TLS is enabled")
		}
		validateTLSMTLSMode(ve, cfg.TLS.MTLSMode)
	}

	// Max message size.
	if cfg.MaxMessageSize <= 0 {
		ve.add("max_message_size must be > 0")
	}

	validateOptionalDatabase(ve, cfg.Database)
	validateSemantic(ve, cfg.Semantic)

	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateControlPlaneConfig checks all required fields for ControlPlaneConfig.
func ValidateControlPlaneConfig(cfg ControlPlaneConfig) error {
	ve := &ValidationError{}

	validateAddr(ve, "http_listen_addr", cfg.HTTPListenAddr)
	validateAddr(ve, "grpc_listen_addr", cfg.GRPCListenAddr)

	// Database is required for the control plane.
	if cfg.Database.URL == "" {
		ve.add("database.url is required for control-plane")
	} else {
		validateURL(ve, "database.url", cfg.Database.URL)
	}

	if cfg.Database.MaxConns < 1 {
		ve.add("database.max_conns must be >= 1")
	}

	// Redis is optional but if set, must be valid.
	if cfg.Redis.URL != "" {
		validateURL(ve, "redis.url", cfg.Redis.URL)
	}

	// TLS consistency.
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" {
			ve.add("tls.cert_file is required when TLS is enabled")
		}
		if cfg.TLS.KeyFile == "" {
			ve.add("tls.key_file is required when TLS is enabled")
		}
	}

	// Auth: if JWKS URL is set, issuer should also be set.
	if cfg.Auth.JWKSURL != "" {
		validateURL(ve, "auth.jwks_url", cfg.Auth.JWKSURL)
		if cfg.Auth.Issuer == "" {
			ve.add("auth.issuer should be set when auth.jwks_url is configured")
		}
	}

	// Approvals timeout.
	if cfg.Approvals.DefaultTimeout < 0 {
		ve.add("approvals.default_timeout must not be negative")
	}

	// Telemetry log level.
	validateLogLevel(ve, cfg.Telemetry.LogLevel)
	validateLogFormat(ve, cfg.Telemetry.LogFormat)
	validateSemantic(ve, cfg.Semantic)

	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateAgentConfig checks all required fields for AgentConfig.
func ValidateAgentConfig(cfg AgentConfig) error {
	ve := &ValidationError{}

	if cfg.Wrapper.Enabled && cfg.Wrapper.MaxProcesses < 1 {
		ve.add("wrapper.max_processes must be >= 1 when wrapper is enabled")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		ve.add("tenant_id must not be empty")
	}
	if strings.TrimSpace(cfg.AgentID) == "" {
		ve.add("agent_id must not be empty")
	}

	if cfg.PolicyRefreshInterval <= 0 {
		ve.add("policy_refresh_interval must be > 0")
	}

	if cfg.Discovery.ScanInterval <= 0 {
		ve.add("discovery.scan_interval must be > 0")
	}

	if len(cfg.Discovery.ConfigPaths) == 0 {
		ve.add("discovery.config_paths must not be empty")
	}

	validateOptionalDatabase(ve, cfg.Database)
	validateSemantic(ve, cfg.Semantic)

	validateLogLevel(ve, cfg.Telemetry.LogLevel)
	validateLogFormat(ve, cfg.Telemetry.LogFormat)

	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ValidateSensorConfig checks sensor settings.
func ValidateSensorConfig(cfg SensorConfig) error {
	ve := &ValidationError{}

	if cfg.EBPF.EventBufferSize < 0 {
		ve.add("ebpf.event_buffer_size must not be negative")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		ve.add("tenant_id must not be empty")
	}
	if strings.TrimSpace(cfg.AgentID) == "" {
		ve.add("agent_id must not be empty")
	}
	validateOptionalDatabase(ve, cfg.Database)
	validateLogLevel(ve, cfg.Telemetry.LogLevel)
	validateLogFormat(ve, cfg.Telemetry.LogFormat)

	if ve.HasErrors() {
		return ve
	}
	return nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func validateAddr(ve *ValidationError, field, addr string) {
	if addr == "" {
		ve.add(field + " must not be empty")
		return
	}
	// Must start with ":" or contain ":" for host:port.
	if !strings.Contains(addr, ":") {
		ve.add(fmt.Sprintf("%s %q is not a valid host:port address", field, addr))
	}
}

func validateURL(ve *ValidationError, field, rawURL string) {
	_, err := url.Parse(rawURL)
	if err != nil {
		ve.add(fmt.Sprintf("%s %q is not a valid URL: %v", field, rawURL, err))
	}
}

func validateOptionalDatabase(ve *ValidationError, db DatabaseConfig) {
	if db.URL == "" {
		return
	}
	validateURL(ve, "database.url", db.URL)
	if db.MaxConns < 1 {
		ve.add("database.max_conns must be >= 1 when database.url is configured")
	}
}

func validateSemantic(ve *ValidationError, cfg SemanticConfig) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "", "stub":
		// valid
	case "http":
		if strings.TrimSpace(cfg.Endpoint) == "" {
			ve.add("semantic.endpoint is required when semantic.provider=http")
		} else {
			validateURL(ve, "semantic.endpoint", cfg.Endpoint)
		}
	case "openai":
		if strings.TrimSpace(cfg.Endpoint) != "" {
			validateURL(ve, "semantic.endpoint", cfg.Endpoint)
		}
	default:
		ve.add(fmt.Sprintf("semantic.provider %q is not valid (use: stub, http, openai)", cfg.Provider))
	}
	if cfg.Timeout < 0 {
		ve.add("semantic.timeout must not be negative")
	}
}

func validateTLSMTLSMode(ve *ValidationError, mode string) {
	switch mode {
	case "", "disabled", "optional", "required":
		// valid
	default:
		ve.add(fmt.Sprintf("tls.mtls_mode %q is not valid (use: disabled, optional, required)", mode))
	}
}

func validateLogLevel(ve *ValidationError, level string) {
	switch strings.ToLower(level) {
	case "", "debug", "info", "warn", "error":
		// valid
	default:
		ve.add(fmt.Sprintf("telemetry.log_level %q is not valid (use: debug, info, warn, error)", level))
	}
}

func validateLogFormat(ve *ValidationError, format string) {
	switch strings.ToLower(format) {
	case "", "json", "text":
		// valid
	default:
		ve.add(fmt.Sprintf("telemetry.log_format %q is not valid (use: json, text)", format))
	}
}
