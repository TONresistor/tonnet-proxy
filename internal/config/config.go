// Package config provides YAML-based configuration loading for the proxy.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProxyConfig holds all proxy settings loadable from a YAML file.
type ProxyConfig struct {
	Listen       string            `yaml:"listen"`
	Mode         string            `yaml:"mode"` // "direct" or "auto"
	TONConfig    string            `yaml:"ton_config"`
	DirectoryURL string            `yaml:"directory_url"`
	Retries      int               `yaml:"retries"`
	Rotate       string            `yaml:"rotate"`
	Debug        bool              `yaml:"debug"`
	RPC          map[string]string `yaml:"rpc"`      // ".eth": "https://...", ".sol": "https://..."
	Disabled     []string          `yaml:"disabled"`  // [".btc", ".zil"]
}

// Load reads a YAML config file from path and returns the parsed ProxyConfig.
func Load(path string) (*ProxyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ProxyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
