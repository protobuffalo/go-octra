package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DefaultRPCURL      = "http://46.101.86.250:8080"
	DefaultExplorerURL = "https://octrascan.io"
	DefaultDataDir     = "data"
)

var (
	configPath = filepath.Join(DefaultDataDir, "config.json")
)

// Config holds global CLI settings that are not wallet-specific.
type Config struct {
	RPCURL      string `json:"rpc_url,omitempty"`
	ExplorerURL string `json:"explorer_url,omitempty"`
	DataDir     string `json:"data_dir,omitempty"`
}

// Load reads config from disk, falling back to defaults.
// Environment variables override file values:
//
//	OCTRA_RPC_URL, OCTRA_EXPLORER_URL, OCTRA_DATA_DIR
func Load() *Config {
	c := &Config{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, c)
	}

	// Env overrides
	if v := os.Getenv("OCTRA_RPC_URL"); v != "" {
		c.RPCURL = v
	}
	if v := os.Getenv("OCTRA_EXPLORER_URL"); v != "" {
		c.ExplorerURL = v
	}
	if v := os.Getenv("OCTRA_DATA_DIR"); v != "" {
		c.DataDir = v
	}

	// Apply defaults for empty fields
	if c.RPCURL == "" {
		c.RPCURL = DefaultRPCURL
	}
	if c.ExplorerURL == "" {
		c.ExplorerURL = DefaultExplorerURL
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}

	return c
}

// Save writes the config to disk.
func (c *Config) Save() error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}

// WalletDir returns the data directory (where .oct files and manifest live).
func (c *Config) WalletDir() string {
	return c.DataDir
}

// WalletFile returns the default wallet file path.
func (c *Config) WalletFile() string {
	return filepath.Join(c.DataDir, "wallet.oct")
}

// ManifestFile returns the accounts manifest path.
func (c *Config) ManifestFile() string {
	return filepath.Join(c.DataDir, "accounts.json")
}

// TxCacheDir returns the transaction cache directory.
func (c *Config) TxCacheDir() string {
	return filepath.Join(c.DataDir, "txcache")
}
