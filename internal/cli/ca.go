package cli

import (
	"fmt"
	"os"

	"github.com/sns45/svidmint/internal/ca"
	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate authority commands",
	}

	cmd.AddCommand(newCAInitCmd())
	cmd.AddCommand(newCARotateCmd())
	cmd.AddCommand(newCAExportCmd())

	return cmd
}

func newCAInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new self-signed CA",
		RunE:  runCAInit,
	}

	cmd.Flags().String("trust-domain", "", "SPIFFE trust domain (required)")
	cmd.Flags().String("key-type", "ec-p256", "Key type (ec-p256, ec-p384)")
	cmd.Flags().String("root-key-path", "root.key", "Path to write root private key")
	cmd.Flags().String("root-cert-path", "root.crt", "Path to write root certificate")
	cmd.Flags().Bool("force", false, "Overwrite existing files")
	_ = cmd.MarkFlagRequired("trust-domain")

	return cmd
}

func runCAInit(cmd *cobra.Command, args []string) error {
	trustDomain, _ := cmd.Flags().GetString("trust-domain")
	rootKeyPath, _ := cmd.Flags().GetString("root-key-path")
	rootCertPath, _ := cmd.Flags().GetString("root-cert-path")
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		if _, err := os.Stat(rootKeyPath); err == nil {
			return fmt.Errorf("root key already exists at %s (use --force to overwrite)", rootKeyPath)
		}
		if _, err := os.Stat(rootCertPath); err == nil {
			return fmt.Errorf("root cert already exists at %s (use --force to overwrite)", rootCertPath)
		}
	} else {
		// Remove existing files so NewSelfSignedCA generates fresh ones
		os.Remove(rootKeyPath)
		os.Remove(rootCertPath)
	}

	cfg := ca.SelfSignedCAConfig{
		TrustDomain:  trustDomain,
		RootKeyPath:  rootKeyPath,
		RootCertPath: rootCertPath,
		SigningTTL:   "720h",
		DefaultTTL:   "1h",
		MaxTTL:       "24h",
	}

	_, err := ca.NewSelfSignedCA(cfg)
	if err != nil {
		return fmt.Errorf("initializing CA: %w", err)
	}

	cmd.Printf("CA initialized for trust domain %s\n", trustDomain)
	return nil
}

func newCARotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the intermediate signing key",
		RunE:  runCARotate,
	}

	cmd.Flags().String("trust-domain", "", "SPIFFE trust domain (required)")
	cmd.Flags().String("root-key-path", "root.key", "Path to root private key")
	cmd.Flags().String("root-cert-path", "root.crt", "Path to root certificate")
	_ = cmd.MarkFlagRequired("trust-domain")

	return cmd
}

func runCARotate(cmd *cobra.Command, args []string) error {
	trustDomain, _ := cmd.Flags().GetString("trust-domain")
	rootKeyPath, _ := cmd.Flags().GetString("root-key-path")
	rootCertPath, _ := cmd.Flags().GetString("root-cert-path")

	cfg := ca.SelfSignedCAConfig{
		TrustDomain:  trustDomain,
		RootKeyPath:  rootKeyPath,
		RootCertPath: rootCertPath,
		SigningTTL:   "720h",
		DefaultTTL:   "1h",
		MaxTTL:       "24h",
	}

	_, err := ca.NewSelfSignedCA(cfg)
	if err != nil {
		return fmt.Errorf("rotating CA: %w", err)
	}

	cmd.Println("Intermediate signing key rotated successfully")
	return nil
}

func newCAExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the root CA certificate",
		RunE:  runCAExport,
	}

	cmd.Flags().String("format", "pem", "Output format (pem, der)")
	cmd.Flags().String("root-cert-path", "root.crt", "Path to root certificate")

	return cmd
}

func runCAExport(cmd *cobra.Command, args []string) error {
	rootCertPath, _ := cmd.Flags().GetString("root-cert-path")
	format, _ := cmd.Flags().GetString("format")

	data, err := os.ReadFile(rootCertPath)
	if err != nil {
		return fmt.Errorf("reading root certificate: %w", err)
	}

	switch format {
	case "pem":
		cmd.Print(string(data))
	case "der":
		// For DER, we would need to decode PEM and output raw bytes.
		// For now, just output the raw file content.
		cmd.OutOrStdout().Write(data)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}
