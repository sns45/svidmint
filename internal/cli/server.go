package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/sns45/svidmint/internal/attestor"
	"github.com/sns45/svidmint/internal/ca"
	"github.com/sns45/svidmint/internal/config"
	"github.com/sns45/svidmint/internal/entry"
	"github.com/sns45/svidmint/internal/server"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server commands",
	}
	cmd.AddCommand(newServerStartCmd())
	cmd.AddCommand(newServerConfigCmd())
	return cmd
}

func newServerStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the svidmint server",
		RunE:  runServerStart,
	}
	cmd.Flags().String("config", "", "path to config file")
	cmd.Flags().String("listen", "", "listen address (overrides config)")
	cmd.Flags().String("trust-domain", "", "SPIFFE trust domain (overrides config)")
	cmd.Flags().String("entries", "", "path to YAML file with registration entries to preload")
	cmd.Flags().String("db", "", "path to database file (overrides config)")
	return cmd
}

func newServerConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Print effective server configuration",
		RunE:  runServerConfig,
	}
	cmd.Flags().String("config", "", "path to config file")
	return cmd
}

func loadEffectiveConfig(cmd *cobra.Command) (*config.Config, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		// Also check persistent flag from root
		cfgPath, _ = cmd.Root().PersistentFlags().GetString("config")
	}
	// If the config path is the default value and the file does not exist,
	// treat it as no config file (use defaults only).
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			cfgPath = ""
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return cfg, nil
}

func runServerStart(cmd *cobra.Command, args []string) error {
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return err
	}

	// Apply flag overrides
	if listen, _ := cmd.Flags().GetString("listen"); listen != "" {
		cfg.Server.Listen = listen
	}
	if td, _ := cmd.Flags().GetString("trust-domain"); td != "" {
		cfg.TrustDomain = td
	}
	if dbPath, _ := cmd.Flags().GetString("db"); dbPath != "" {
		cfg.Storage.DSN = dbPath
	}

	if cfg.TrustDomain == "" {
		return fmt.Errorf("trust_domain is required (set via config or --trust-domain)")
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer logger.Sync()

	// Initialize CA
	caImpl, err := ca.NewSelfSignedCA(ca.SelfSignedCAConfig{
		TrustDomain:  cfg.TrustDomain,
		KeyType:      cfg.CA.KeyType,
		RootKeyPath:  cfg.CA.RootKeyPath,
		RootCertPath: cfg.CA.RootCertPath,
		SigningTTL:   cfg.CA.SigningTTL,
		DefaultTTL:   cfg.CA.DefaultSVIDTTL,
		MaxTTL:       cfg.CA.MaxSVIDTTL,
	})
	if err != nil {
		return fmt.Errorf("initializing CA: %w", err)
	}

	// Initialize store
	store, err := entry.NewSQLiteStore(cfg.Storage.DSN)
	if err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}
	defer store.Close()

	// Preload entries from YAML if specified
	if entriesPath, _ := cmd.Flags().GetString("entries"); entriesPath != "" {
		entries, err := entry.LoadEntriesFromFile(entriesPath)
		if err != nil {
			return fmt.Errorf("loading entries from %s: %w", entriesPath, err)
		}
		ctx := context.Background()
		for _, e := range entries {
			if err := store.Create(ctx, e); err != nil {
				logger.Warn("failed to preload entry", zap.String("id", e.ID), zap.Error(err))
			}
		}
		logger.Info("preloaded registration entries", zap.Int("count", len(entries)))
	}

	// Build attestor registry from config
	registry := buildAttestorRegistry(cfg, logger)

	// Create and start server
	srv, err := server.New(caImpl, registry, store, cfg, logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting svidmint server", zap.String("listen", cfg.Server.Listen), zap.String("trust_domain", cfg.TrustDomain))
		errCh <- srv.Start(ctx)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down server")
		shutdownCtx := context.Background()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down server: %w", err)
		}
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

func buildAttestorRegistry(cfg *config.Config, logger *zap.Logger) *attestor.Registry {
	var attestors []attestor.Attestor

	if cfg.Attestors.AWSLambda != nil && cfg.Attestors.AWSLambda.Enabled {
		attestors = append(attestors, attestor.NewAWSLambdaAttestor(attestor.AWSLambdaAttestorConfig{
			AllowedAccountIDs: cfg.Attestors.AWSLambda.AllowedAccountIDs,
			AllowedRegions:    cfg.Attestors.AWSLambda.AllowedRegions,
		}))
		logger.Info("registered attestor", zap.String("name", "aws_sts"))
	}

	if cfg.Attestors.CloudflareWorkers != nil && cfg.Attestors.CloudflareWorkers.Enabled {
		var teams []attestor.CloudflareTeamConfig
		for _, t := range cfg.Attestors.CloudflareWorkers.Teams {
			teams = append(teams, attestor.CloudflareTeamConfig{
				Name:     t.Name,
				CertsURL: t.CertsURL,
			})
		}
		attestors = append(attestors, attestor.NewCloudflareWorkersAttestor(attestor.CloudflareWorkersAttestorConfig{
			Teams: teams,
		}))
		logger.Info("registered attestor", zap.String("name", "cloudflare_workers"))
	}

	if cfg.Attestors.GitHubOIDC != nil && cfg.Attestors.GitHubOIDC.Enabled {
		attestors = append(attestors, attestor.NewGitHubOIDCAttestor(attestor.GitHubOIDCAttestorConfig{
			AllowedRepositories: cfg.Attestors.GitHubOIDC.AllowedRepositories,
			Issuer:              cfg.Attestors.GitHubOIDC.Issuer,
		}))
		logger.Info("registered attestor", zap.String("name", "github_oidc"))
	}

	if cfg.Attestors.DenoOIDC != nil && cfg.Attestors.DenoOIDC.Enabled {
		attestors = append(attestors, attestor.NewDenoDeployAttestor(attestor.DenoDeployAttestorConfig{
			AllowedIssuers: []string{cfg.Attestors.DenoOIDC.Issuer},
		}))
		logger.Info("registered attestor", zap.String("name", "deno_oidc"))
	}

	if len(attestors) == 0 {
		logger.Warn("no attestors enabled in configuration")
	}

	return attestor.NewRegistry(attestors...)
}

func runServerConfig(cmd *cobra.Command, args []string) error {
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	cmd.Print(string(data))
	return nil
}
