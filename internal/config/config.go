package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type ProviderRateLimit struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type Settings struct {
	ChaosAPIKey          string                       `json:"chaos_api_key"`
	RapidDNSAPIKey       string                       `json:"rapid_dns_api_key"`
	DNSResolvers         []string                     `json:"dns_resolvers"`
	EnableHostsCollision bool                         `json:"enable_hosts_collision"`
	EnableWebProbe       bool                         `json:"enable_web_probe"`
	HTTPTimeoutSecond    int                          `json:"http_timeout_second"`
	MaxConcurrency       int                          `json:"max_concurrency"`
	MaxRetries           int                          `json:"max_retries"`
	ProviderRateLimit    map[string]ProviderRateLimit `json:"provider_rate_limit"`
}

func DefaultSettings() Settings {
	return Settings{
		HTTPTimeoutSecond:    20,
		MaxConcurrency:       4,
		MaxRetries:           2,
		DNSResolvers:         []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"},
		EnableHostsCollision: true,
		EnableWebProbe:       true,
		ProviderRateLimit: map[string]ProviderRateLimit{
			"chaos":           {RequestsPerSecond: 2},
			"crtsh":           {RequestsPerSecond: 1.5},
			"ipthc":           {RequestsPerSecond: 1},
			"ipthc_subdomain": {RequestsPerSecond: 1},
			"urlscan":         {RequestsPerSecond: 1},
			"myssl":           {RequestsPerSecond: 1},
			"rapiddns":        {RequestsPerSecond: 1},
			"hackertarget":    {RequestsPerSecond: 1},
		},
	}
}

func (s Settings) HTTPTimeout() time.Duration {
	if s.HTTPTimeoutSecond <= 0 {
		return 20 * time.Second
	}
	return time.Duration(s.HTTPTimeoutSecond) * time.Second
}

func pathForConfig() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	appDir := filepath.Join(dir, "subdomain-tools")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(appDir, "settings.json"), nil
}

func Load() (Settings, error) {
	cfg := DefaultSettings()
	p, err := pathForConfig()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultSettings(), err
	}
	return cfg, nil
}

func Save(cfg Settings) error {
	p, err := pathForConfig()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}
