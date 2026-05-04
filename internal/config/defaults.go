package config

import "time"

// GatewayDefaults returns the default GatewayConfig with security-conservative settings.
func GatewayDefaults() GatewayConfig {
	return GatewayConfig{
		ListenAddr: ":8443",
		TenantID:   "00000000-0000-0000-0000-000000000001",
		AgentID:    "00000000-0000-0000-0000-000000000002",
		ServerID:   "00000000-0000-0000-0000-000000000003",
		TLS: TLSConfig{
			Enabled:  false, // disabled for dev; always enable in production
			MTLSMode: "disabled",
		},
		ControlPlane: ControlPlaneClientConfig{
			Address:  "localhost:9090",
			Timeout:  10 * time.Second,
			Insecure: true, // dev default; disable in production
		},
		Redis: RedisConfig{
			URL:          "redis://localhost:6379",
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
		Database: DatabaseConfig{
			MaxConns:        10,
			MinConns:        1,
			MaxConnLifetime: 30 * time.Minute,
			MaxConnIdleTime: 5 * time.Minute,
		},
		Pipeline: PipelineConfig{
			MaxEvalDuration: 100 * time.Millisecond,
			FailOpen:        false, // fail-closed by default
			MonitorOnlyMode: false,
			SemanticEnabled: true,
		},
		Semantic: SemanticConfig{
			Provider:       "stub",
			Timeout:        2 * time.Second,
			FallbackToStub: true,
		},
		Telemetry: TelemetryConfig{
			ServiceName:    "mcpids-gateway",
			PrometheusAddr: ":9464",
			LogLevel:       "info",
			LogFormat:      "json",
		},
		MaxMessageSize: 4 * 1024 * 1024, // 4 MiB
	}
}

// ControlPlaneDefaults returns the default ControlPlaneConfig.
func ControlPlaneDefaults() ControlPlaneConfig {
	return ControlPlaneConfig{
		GRPCListenAddr: ":9090",
		HTTPListenAddr: ":8080",
		Database: DatabaseConfig{
			URL:             "postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable",
			MaxConns:        20,
			MinConns:        2,
			MaxConnLifetime: 30 * time.Minute,
			MaxConnIdleTime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			URL:      "redis://localhost:6379",
			PoolSize: 20,
		},
		Auth: AuthConfig{
			JWKSRefreshInterval: 5 * time.Minute,
		},
		Telemetry: TelemetryConfig{
			ServiceName:    "mcpids-control-plane",
			PrometheusAddr: ":9465",
			LogLevel:       "info",
			LogFormat:      "json",
		},
		Semantic: SemanticConfig{
			Provider:       "stub",
			Timeout:        2 * time.Second,
			FallbackToStub: true,
		},
		Rules: RulesConfig{
			ReloadInterval: 60 * time.Second,
		},
		Approvals: ApprovalsConfig{
			DefaultTimeout: 5 * time.Minute,
		},
	}
}

// AgentDefaults returns the default AgentConfig.
func AgentDefaults() AgentConfig {
	return AgentConfig{
		TenantID:  "00000000-0000-0000-0000-000000000001",
		AgentID:   "00000000-0000-0000-0000-000000000002",
		AgentName: "dev-agent",
		ControlPlane: ControlPlaneClientConfig{
			Address:  "localhost:9090",
			Timeout:  10 * time.Second,
			Insecure: true,
		},
		Redis: RedisConfig{
			URL:      "redis://localhost:6379",
			PoolSize: 5,
		},
		Database: DatabaseConfig{
			MaxConns:        5,
			MinConns:        1,
			MaxConnLifetime: 30 * time.Minute,
			MaxConnIdleTime: 5 * time.Minute,
		},
		Discovery: DiscoveryConfig{
			ConfigPaths: []string{
				"~/.cursor/mcp.json",
				"~/.claude.json",
				"~/.config/claude/claude_desktop_config.json",
				"~/.config/Code/User/settings.json", // VS Code MCP config
			},
			ScanInterval: 30 * time.Second,
		},
		Wrapper: WrapperConfig{
			Enabled:      true,
			MaxProcesses: 10,
		},
		PolicyRefreshInterval: 30 * time.Second,
		Telemetry: TelemetryConfig{
			ServiceName: "mcpids-agent",
			LogLevel:    "info",
			LogFormat:   "json",
		},
		Semantic: SemanticConfig{
			Provider:       "stub",
			Timeout:        2 * time.Second,
			FallbackToStub: true,
		},
	}
}

// SensorDefaults returns the default SensorConfig.
func SensorDefaults() SensorConfig {
	return SensorConfig{
		TenantID: "00000000-0000-0000-0000-000000000001",
		AgentID:  "00000000-0000-0000-0000-000000000002",
		ControlPlane: ControlPlaneClientConfig{
			Address:  "localhost:9090",
			Timeout:  10 * time.Second,
			Insecure: true,
		},
		Database: DatabaseConfig{
			MaxConns:        5,
			MinConns:        1,
			MaxConnLifetime: 30 * time.Minute,
			MaxConnIdleTime: 5 * time.Minute,
		},
		EBPF: EBPFConfig{
			Enabled:         false,
			AttachKprobes:   true,
			AttachUprobes:   false,
			EventBufferSize: 1024,
		},
		Telemetry: TelemetryConfig{
			ServiceName:    "mcpids-sensor",
			PrometheusAddr: ":9467",
			LogLevel:       "info",
			LogFormat:      "json",
		},
	}
}
