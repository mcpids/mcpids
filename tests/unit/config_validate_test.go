package unit

import (
	"testing"
	"time"

	"github.com/mcpids/mcpids/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateGatewayConfig_Defaults(t *testing.T) {
	cfg := config.GatewayDefaults()
	err := config.ValidateGatewayConfig(cfg)
	assert.NoError(t, err, "default gateway config should be valid")
}

func TestValidateGatewayConfig_EmptyAddr(t *testing.T) {
	cfg := config.GatewayDefaults()
	cfg.ListenAddr = ""
	err := config.ValidateGatewayConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_addr")
}

func TestValidateGatewayConfig_BadPipelineTimeout(t *testing.T) {
	cfg := config.GatewayDefaults()
	cfg.Pipeline.MaxEvalDuration = 0
	err := config.ValidateGatewayConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_eval_duration")
}

func TestValidateGatewayConfig_TLSWithoutCert(t *testing.T) {
	cfg := config.GatewayDefaults()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	err := config.ValidateGatewayConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file")
	assert.Contains(t, err.Error(), "key_file")
}

func TestValidateGatewayConfig_TLSBadMTLSMode(t *testing.T) {
	cfg := config.GatewayDefaults()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert"
	cfg.TLS.KeyFile = "/path/to/key"
	cfg.TLS.MTLSMode = "invalid"
	err := config.ValidateGatewayConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mtls_mode")
}

func TestValidateGatewayConfig_MaxMessageSize(t *testing.T) {
	cfg := config.GatewayDefaults()
	cfg.MaxMessageSize = -1
	err := config.ValidateGatewayConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_message_size")
}

func TestValidateControlPlaneConfig_Defaults(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	err := config.ValidateControlPlaneConfig(cfg)
	assert.NoError(t, err, "default control-plane config should be valid")
}

func TestValidateControlPlaneConfig_NoDB(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	cfg.Database.URL = ""
	err := config.ValidateControlPlaneConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database.url")
}

func TestValidateControlPlaneConfig_BadMaxConns(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	cfg.Database.MaxConns = 0
	err := config.ValidateControlPlaneConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_conns")
}

func TestValidateControlPlaneConfig_BadLogLevel(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	cfg.Telemetry.LogLevel = "verbose"
	err := config.ValidateControlPlaneConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log_level")
}

func TestValidateAgentConfig_Defaults(t *testing.T) {
	cfg := config.AgentDefaults()
	err := config.ValidateAgentConfig(cfg)
	assert.NoError(t, err, "default agent config should be valid")
}

func TestValidateAgentConfig_BadRefreshInterval(t *testing.T) {
	cfg := config.AgentDefaults()
	cfg.PolicyRefreshInterval = 0
	err := config.ValidateAgentConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy_refresh_interval")
}

func TestValidateAgentConfig_EmptyConfigPaths(t *testing.T) {
	cfg := config.AgentDefaults()
	cfg.Discovery.ConfigPaths = nil
	err := config.ValidateAgentConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config_paths")
}

func TestValidateAgentConfig_WrapperMaxProcesses(t *testing.T) {
	cfg := config.AgentDefaults()
	cfg.Wrapper.Enabled = true
	cfg.Wrapper.MaxProcesses = 0
	err := config.ValidateAgentConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_processes")
}

func TestValidateControlPlaneConfig_AuthWithoutIssuer(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	cfg.Auth.JWKSURL = "https://example.com/.well-known/jwks.json"
	cfg.Auth.Issuer = ""
	err := config.ValidateControlPlaneConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth.issuer")
}

func TestValidateControlPlaneConfig_NegativeApprovalTimeout(t *testing.T) {
	cfg := config.ControlPlaneDefaults()
	cfg.Approvals.DefaultTimeout = -1 * time.Second
	err := config.ValidateControlPlaneConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_timeout")
}
