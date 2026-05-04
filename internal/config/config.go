package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// LoadGatewayConfig loads gateway configuration from file + environment.
// Environment variables override file values. Prefix: MCPIDS_GATEWAY_
func LoadGatewayConfig(configFile string) (GatewayConfig, error) {
	cfg := GatewayDefaults()
	if err := load("MCPIDS_GATEWAY", configFile, &cfg); err != nil {
		return GatewayConfig{}, err
	}
	if err := ValidateGatewayConfig(cfg); err != nil {
		return GatewayConfig{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// LoadControlPlaneConfig loads control-plane configuration.
// Prefix: MCPIDS_CP_
func LoadControlPlaneConfig(configFile string) (ControlPlaneConfig, error) {
	cfg := ControlPlaneDefaults()
	if err := load("MCPIDS_CP", configFile, &cfg); err != nil {
		return ControlPlaneConfig{}, err
	}
	if err := ValidateControlPlaneConfig(cfg); err != nil {
		return ControlPlaneConfig{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// LoadAgentConfig loads agent configuration.
// Prefix: MCPIDS_AGENT_
func LoadAgentConfig(configFile string) (AgentConfig, error) {
	cfg := AgentDefaults()
	if err := load("MCPIDS_AGENT", configFile, &cfg); err != nil {
		return AgentConfig{}, err
	}
	if err := ValidateAgentConfig(cfg); err != nil {
		return AgentConfig{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// LoadSensorConfig loads sensor configuration.
// Prefix: MCPIDS_SENSOR_
func LoadSensorConfig(configFile string) (SensorConfig, error) {
	cfg := SensorDefaults()
	if err := load("MCPIDS_SENSOR", configFile, &cfg); err != nil {
		return SensorConfig{}, err
	}
	if err := ValidateSensorConfig(cfg); err != nil {
		return SensorConfig{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// load is the generic viper-based loader used by all component configs.
func load(envPrefix, configFile string, out any) error {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("config: read %q: %w", configFile, err)
		}
	}

	if err := v.Unmarshal(out); err != nil {
		return fmt.Errorf("config: unmarshal: %w", err)
	}

	return nil
}
