// Package cli implements the command line interface for svidmint.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	versionStr string
	commitStr  string
	dateStr    string
)

// SetVersionInfo stores build metadata for use in version commands.
func SetVersionInfo(version, commit, date string) {
	versionStr = version
	commitStr = commit
	dateStr = date
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "svidmint",
		Short:        "SPIFFE-compatible workload identity for serverless/edge environments",
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().String("config", ".svidmint.yaml", "config file path")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, text)")

	rootCmd.AddCommand(newServerCmd())
	rootCmd.AddCommand(newEntryCmd())
	rootCmd.AddCommand(newBundleCmd())
	rootCmd.AddCommand(newTokenCmd())
	rootCmd.AddCommand(newCACmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// Execute runs the root CLI command.
func Execute() error {
	return newRootCmd().Execute()
}

// Stub subcommands (will be implemented in later tasks)

func newBundleCmd() *cobra.Command {
	return &cobra.Command{Use: "bundle", Short: "Trust bundle commands"}
}

func newTokenCmd() *cobra.Command {
	return &cobra.Command{Use: "token", Short: "Token commands"}
}


