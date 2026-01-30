// Copyright 2026 dotandev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Network string

const (
	NetworkPublic     Network = "public"
	NetworkTestnet    Network = "testnet"
	NetworkFuturenet  Network = "futurenet"
	NetworkStandalone Network = "standalone"
)

var validNetworks = map[string]bool{
	string(NetworkPublic):     true,
	string(NetworkTestnet):    true,
	string(NetworkFuturenet):  true,
	string(NetworkStandalone): true,
}

type Config struct {
	RpcUrl        string
	Network       Network
	SimulatorPath string
	LogLevel      string
	CachePath     string
}

var defaultConfig = &Config{
	RpcUrl:        "https://soroban-testnet.stellar.org",
	Network:       NetworkTestnet,
	SimulatorPath: "",
	LogLevel:      "info",
	CachePath:     filepath.Join(os.ExpandEnv("$HOME"), ".erst", "cache"),
}

func Load() (*Config, error) {
	cfg := &Config{
		RpcUrl:        getEnv("ERST_RPC_URL", defaultConfig.RpcUrl),
		Network:       Network(getEnv("ERST_NETWORK", string(defaultConfig.Network))),
		SimulatorPath: getEnv("ERST_SIMULATOR_PATH", defaultConfig.SimulatorPath),
		LogLevel:      getEnv("ERST_LOG_LEVEL", defaultConfig.LogLevel),
		CachePath:     getEnv("ERST_CACHE_PATH", defaultConfig.CachePath),
	}

	if err := cfg.loadFromFile(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) loadFromFile() error {
	paths := []string{
		".erst.toml",
		filepath.Join(os.ExpandEnv("$HOME"), ".erst.toml"),
		"/etc/erst/config.toml",
	}

	for _, path := range paths {
		if err := c.loadTOML(path); err == nil {
			return nil
		}
	}

	return nil
}

func (c *Config) loadTOML(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return c.parseTOML(string(data))
}

func (c *Config) parseTOML(content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

		switch key {
		case "rpc_url":
			c.RpcUrl = value
		case "network":
			c.Network = Network(value)
		case "simulator_path":
			c.SimulatorPath = value
		case "log_level":
			c.LogLevel = value
		case "cache_path":
			c.CachePath = value
		}
	}

	return nil
}

func (c *Config) Validate() error {
	if c.RpcUrl == "" {
		return fmt.Errorf("rpc_url cannot be empty")
	}

	if !validNetworks[string(c.Network)] {
		return fmt.Errorf("invalid network: %s (valid: public, testnet, futurenet, standalone)", c.Network)
	}

	return nil
}

func (c *Config) NetworkURL() string {
	switch c.Network {
	case NetworkPublic:
		return "https://soroban.stellar.org"
	case NetworkTestnet:
		return "https://soroban-testnet.stellar.org"
	case NetworkFuturenet:
		return "https://soroban-futurenet.stellar.org"
	case NetworkStandalone:
		return "http://localhost:8000"
	default:
		return c.RpcUrl
	}
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{RPC: %s, Network: %s, LogLevel: %s, CachePath: %s}",
		c.RpcUrl, c.Network, c.LogLevel, c.CachePath,
	)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func DefaultConfig() *Config {
	cfg := &Config{
		RpcUrl:        defaultConfig.RpcUrl,
		Network:       defaultConfig.Network,
		SimulatorPath: defaultConfig.SimulatorPath,
		LogLevel:      defaultConfig.LogLevel,
		CachePath:     defaultConfig.CachePath,
	}
	return cfg
}

func NewConfig(rpcUrl string, network Network) *Config {
	return &Config{
		RpcUrl:        rpcUrl,
		Network:       network,
		SimulatorPath: defaultConfig.SimulatorPath,
		LogLevel:      defaultConfig.LogLevel,
		CachePath:     defaultConfig.CachePath,
	}
}

func (c *Config) WithSimulatorPath(path string) *Config {
	c.SimulatorPath = path
	return c
}

func (c *Config) WithLogLevel(level string) *Config {
	c.LogLevel = level
	return c
}

func (c *Config) WithCachePath(path string) *Config {
	c.CachePath = path
	return c
}
