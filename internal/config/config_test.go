package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.Server.Listen)
	assert.Equal(t, "self-signed", cfg.CA.Type)
	assert.Equal(t, "ec-p256", cfg.CA.KeyType)
	assert.Equal(t, "5m", cfg.CA.DefaultSVIDTTL)
	assert.Equal(t, "1h", cfg.CA.MaxSVIDTTL)
	assert.Equal(t, "24h", cfg.CA.SigningTTL)
	assert.Equal(t, "sqlite", cfg.Storage.Type)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "test.yaml")
	err := os.WriteFile(cfgFile, []byte(`
trust_domain: example.org
server:
  listen: ":9443"
ca:
  type: self-signed
  key_type: ec-p384
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, "example.org", cfg.TrustDomain)
	assert.Equal(t, ":9443", cfg.Server.Listen)
	assert.Equal(t, "ec-p384", cfg.CA.KeyType)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("SMINT_TRUST_DOMAIN", "envdomain.test")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "envdomain.test", cfg.TrustDomain)
}
