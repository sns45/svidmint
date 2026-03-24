package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/sns45/svidmint/internal/entry"
)

const defaultDBPath = "svidmint.db"

func newEntryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "entry",
		Short: "Registration entry commands",
	}
	cmd.AddCommand(newEntryCreateCmd())
	cmd.AddCommand(newEntryListCmd())
	cmd.AddCommand(newEntryShowCmd())
	cmd.AddCommand(newEntryUpdateCmd())
	cmd.AddCommand(newEntryDeleteCmd())
	return cmd
}

func openStore(cmd *cobra.Command) (entry.Store, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	return entry.NewJSONStore(dbPath)
}

func newEntryCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new registration entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			spiffeID, _ := cmd.Flags().GetString("spiffe-id")
			attestor, _ := cmd.Flags().GetString("attestor")
			selectors, _ := cmd.Flags().GetStringSlice("selector")
			ttl, _ := cmd.Flags().GetInt("ttl")
			id, _ := cmd.Flags().GetString("id")

			// Validate SPIFFE ID
			if _, err := spiffeid.FromString(spiffeID); err != nil {
				return fmt.Errorf("invalid SPIFFE ID %q: %w", spiffeID, err)
			}

			if attestor == "" {
				return fmt.Errorf("attestor is required")
			}
			if len(selectors) == 0 {
				return fmt.Errorf("at least one selector is required")
			}

			// Auto-generate UUID if not provided
			if id == "" {
				id = uuid.New().String()
			}

			store, err := openStore(cmd)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}
			defer store.Close()

			e := &entry.RegistrationEntry{
				ID:        id,
				SpiffeID:  spiffeID,
				Attestor:  attestor,
				Selectors: selectors,
				TTL:       ttl,
			}

			if err := store.Create(context.Background(), e); err != nil {
				return fmt.Errorf("creating entry: %w", err)
			}

			cmd.PrintErrf("Entry created: %s\n", id)
			return nil
		},
	}
	cmd.Flags().String("db", defaultDBPath, "path to the store file")
	cmd.Flags().String("spiffe-id", "", "SPIFFE ID for the entry")
	cmd.Flags().String("attestor", "", "attestor plugin name")
	cmd.Flags().StringSlice("selector", nil, "selector in key:value format (can be repeated)")
	cmd.Flags().Int("ttl", 0, "TTL in seconds")
	cmd.Flags().String("id", "", "entry ID (auto-generated if omitted)")
	_ = cmd.MarkFlagRequired("spiffe-id")
	_ = cmd.MarkFlagRequired("attestor")
	_ = cmd.MarkFlagRequired("selector")
	return cmd
}

func newEntryListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registration entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(cmd)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}
			defer store.Close()

			entries, err := store.List(context.Background())
			if err != nil {
				return fmt.Errorf("listing entries: %w", err)
			}

			attestorFilter, _ := cmd.Flags().GetString("attestor")

			for _, e := range entries {
				if attestorFilter != "" && e.Attestor != attestorFilter {
					continue
				}
				printEntry(cmd, e)
			}
			return nil
		},
	}
	cmd.Flags().String("db", defaultDBPath, "path to the store file")
	cmd.Flags().String("attestor", "", "filter by attestor name")
	return cmd
}

func newEntryShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show a registration entry by ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}

			store, err := openStore(cmd)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}
			defer store.Close()

			e, err := store.Get(context.Background(), id)
			if err != nil {
				return fmt.Errorf("getting entry: %w", err)
			}
			printEntry(cmd, e)
			return nil
		},
	}
	cmd.Flags().String("db", defaultDBPath, "path to the store file")
	cmd.Flags().String("id", "", "entry ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newEntryUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a registration entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}

			store, err := openStore(cmd)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}
			defer store.Close()

			e, err := store.Get(context.Background(), id)
			if err != nil {
				return fmt.Errorf("getting entry: %w", err)
			}

			if cmd.Flags().Changed("spiffe-id") {
				spiffeID, _ := cmd.Flags().GetString("spiffe-id")
				if _, err := spiffeid.FromString(spiffeID); err != nil {
					return fmt.Errorf("invalid SPIFFE ID %q: %w", spiffeID, err)
				}
				e.SpiffeID = spiffeID
			}
			if cmd.Flags().Changed("attestor") {
				e.Attestor, _ = cmd.Flags().GetString("attestor")
			}
			if cmd.Flags().Changed("selector") {
				e.Selectors, _ = cmd.Flags().GetStringSlice("selector")
			}
			if cmd.Flags().Changed("ttl") {
				e.TTL, _ = cmd.Flags().GetInt("ttl")
			}

			if err := store.Update(context.Background(), e); err != nil {
				return fmt.Errorf("updating entry: %w", err)
			}
			cmd.PrintErrf("Entry updated: %s\n", id)
			return nil
		},
	}
	cmd.Flags().String("db", defaultDBPath, "path to the store file")
	cmd.Flags().String("id", "", "entry ID")
	cmd.Flags().String("spiffe-id", "", "SPIFFE ID")
	cmd.Flags().String("attestor", "", "attestor plugin name")
	cmd.Flags().StringSlice("selector", nil, "selector in key:value format")
	cmd.Flags().Int("ttl", 0, "TTL in seconds")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newEntryDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a registration entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := cmd.Flags().GetString("id")
			if id == "" {
				return fmt.Errorf("id is required")
			}

			store, err := openStore(cmd)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}
			defer store.Close()

			if err := store.Delete(context.Background(), id); err != nil {
				return fmt.Errorf("deleting entry: %w", err)
			}
			cmd.PrintErrf("Entry deleted: %s\n", id)
			return nil
		},
	}
	cmd.Flags().String("db", defaultDBPath, "path to the store file")
	cmd.Flags().String("id", "", "entry ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func printEntry(cmd *cobra.Command, e *entry.RegistrationEntry) {
	cmd.Printf("ID:        %s\n", e.ID)
	cmd.Printf("SPIFFE ID: %s\n", e.SpiffeID)
	cmd.Printf("Attestor:  %s\n", e.Attestor)
	cmd.Printf("Selectors: %s\n", strings.Join(e.Selectors, ", "))
	cmd.Printf("TTL:       %d\n", e.TTL)
	cmd.Println()
}
