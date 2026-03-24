// Package config handles svidmint configuration loading and validation.
package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Config is the top level configuration for svidmint.
type Config struct {
	Server      ServerConfig     `mapstructure:"server"`
	TrustDomain string           `mapstructure:"trust_domain"`
	CA          CAConfig         `mapstructure:"ca"`
	Storage     StorageConfig    `mapstructure:"storage"`
	Attestors   AttestorsConfig  `mapstructure:"attestors"`
	Logging     LoggingConfig    `mapstructure:"logging"`
	Metrics     MetricsConfig    `mapstructure:"metrics"`
	Federation  FederationConfig `mapstructure:"federation"`
}

// ServerConfig holds the gRPC/HTTP server settings.
type ServerConfig struct {
	Listen string    `mapstructure:"listen"`
	TLS    TLSConfig `mapstructure:"tls"`
}

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// CAConfig holds certificate authority settings.
type CAConfig struct {
	Type           string `mapstructure:"type"`
	KeyType        string `mapstructure:"key_type"`
	RootKeyPath    string `mapstructure:"root_key_path"`
	RootCertPath   string `mapstructure:"root_cert_path"`
	SigningTTL     string `mapstructure:"signing_ttl"`
	DefaultSVIDTTL string `mapstructure:"default_svid_ttl"`
	MaxSVIDTTL     string `mapstructure:"max_svid_ttl"`
}

// StorageConfig holds backend storage settings.
type StorageConfig struct {
	Type string `mapstructure:"type"`
	DSN  string `mapstructure:"dsn"`
}

// AttestorsConfig holds per platform attestor settings.
type AttestorsConfig struct {
	AWSLambda         *AWSLambdaConfig         `mapstructure:"aws_lambda"`
	CloudflareWorkers *CloudflareWorkersConfig `mapstructure:"cloudflare_workers"`
	GitHubOIDC        *GitHubOIDCConfig        `mapstructure:"github_oidc"`
	DenoOIDC          *DenoOIDCConfig          `mapstructure:"deno_oidc"`
}

// AWSLambdaConfig holds AWS Lambda attestor settings.
type AWSLambdaConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	AllowedAccountIDs []string `mapstructure:"allowed_account_ids"`
	AllowedRegions    []string `mapstructure:"allowed_regions"`
}

// CloudflareWorkersConfig holds Cloudflare Workers attestor settings.
type CloudflareWorkersConfig struct {
	Enabled bool                   `mapstructure:"enabled"`
	Teams   []CloudflareTeamConfig `mapstructure:"teams"`
}

// CloudflareTeamConfig identifies a single Cloudflare Access team.
type CloudflareTeamConfig struct {
	Name     string `mapstructure:"name"`
	CertsURL string `mapstructure:"certs_url"`
}

// GitHubOIDCConfig holds GitHub Actions OIDC attestor settings.
type GitHubOIDCConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	AllowedRepositories []string `mapstructure:"allowed_repositories"`
	Issuer              string   `mapstructure:"issuer"`
}

// DenoOIDCConfig holds Deno Deploy OIDC attestor settings.
type DenoOIDCConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Issuer  string `mapstructure:"issuer"`
}

// LoggingConfig holds structured logging settings.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// MetricsConfig holds Prometheus metrics endpoint settings.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
}

// FederationConfig holds SPIFFE federation bundle settings.
type FederationConfig struct {
	Bundles []FederationBundleConfig `mapstructure:"bundles"`
}

// FederationBundleConfig describes a single federated trust domain bundle endpoint.
type FederationBundleConfig struct {
	TrustDomain     string `mapstructure:"trust_domain"`
	Endpoint        string `mapstructure:"endpoint"`
	Type            string `mapstructure:"type"`
	RefreshInterval string `mapstructure:"refresh_interval"`
}

// Load reads configuration from the given file path (if non empty), applies
// environment variable overrides (prefix SMINT_), and returns the resulting
// Config with sensible defaults populated.
func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetDefault("server.listen", ":8443")
	v.SetDefault("ca.type", "self-signed")
	v.SetDefault("ca.key_type", "ec-p256")
	v.SetDefault("ca.signing_ttl", "24h")
	v.SetDefault("ca.default_svid_ttl", "5m")
	v.SetDefault("ca.max_svid_ttl", "1h")
	v.SetDefault("storage.type", "sqlite")
	v.SetDefault("storage.dsn", "svidmint.db")
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("metrics.listen", ":9090")

	v.SetDefault("trust_domain", "")

	v.SetEnvPrefix("SMINT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
