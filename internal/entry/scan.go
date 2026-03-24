package entry

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// scanEntry scans a single row from a *sql.Row into a RegistrationEntry.
func scanEntry(row *sql.Row) (*RegistrationEntry, error) {
	var e RegistrationEntry
	var selJSON string
	if err := row.Scan(&e.ID, &e.SpiffeID, &e.Attestor, &selJSON, &e.TTL); err != nil {
		return nil, fmt.Errorf("scan entry: %w", err)
	}
	if err := json.Unmarshal([]byte(selJSON), &e.Selectors); err != nil {
		return nil, fmt.Errorf("unmarshal selectors: %w", err)
	}
	return &e, nil
}

// scanEntryRows scans a single row from *sql.Rows into a RegistrationEntry.
// Used by SQLiteStore.
func scanEntryRows(rows *sql.Rows) (*RegistrationEntry, error) {
	var e RegistrationEntry
	var selJSON string
	if err := rows.Scan(&e.ID, &e.SpiffeID, &e.Attestor, &selJSON, &e.TTL); err != nil {
		return nil, fmt.Errorf("scan entry: %w", err)
	}
	if err := json.Unmarshal([]byte(selJSON), &e.Selectors); err != nil {
		return nil, fmt.Errorf("unmarshal selectors: %w", err)
	}
	return &e, nil
}

// scanEntryFromRows is an alias for scanEntryRows, used by PostgresStore.
var scanEntryFromRows = scanEntryRows
