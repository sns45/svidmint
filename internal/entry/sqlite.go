package entry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store backed by a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at path and ensures the
// registration_entries table exists.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS registration_entries (
    id TEXT PRIMARY KEY,
    spiffe_id TEXT NOT NULL,
    attestor TEXT NOT NULL,
    selectors TEXT NOT NULL,
    ttl INTEGER NOT NULL DEFAULT 300,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_entries_attestor ON registration_entries(attestor);
`
	_, err := db.Exec(ddl)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Create(ctx context.Context, entry *RegistrationEntry) error {
	sel, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("marshal selectors: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO registration_entries (id, spiffe_id, attestor, selectors, ttl) VALUES (?, ?, ?, ?, ?)`,
		entry.ID, entry.SpiffeID, entry.Attestor, string(sel), entry.TTL,
	)
	if err != nil {
		return fmt.Errorf("create entry: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Get(ctx context.Context, id string) (*RegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries WHERE id = ?`, id,
	)
	return scanEntry(row)
}

func (s *SQLiteStore) List(ctx context.Context) ([]*RegistrationEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries`,
	)
	if err != nil {
		return nil, fmt.Errorf("list entries: %w", err)
	}
	defer rows.Close()

	var entries []*RegistrationEntry
	for rows.Next() {
		e, err := scanEntryRows(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *SQLiteStore) Update(ctx context.Context, entry *RegistrationEntry) error {
	sel, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("marshal selectors: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE registration_entries SET spiffe_id = ?, attestor = ?, selectors = ?, ttl = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		entry.SpiffeID, entry.Attestor, string(sel), entry.TTL, entry.ID,
	)
	if err != nil {
		return fmt.Errorf("update entry: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM registration_entries WHERE id = ?`, id,
	)
	if err != nil {
		return fmt.Errorf("delete entry: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Match(ctx context.Context, attestorName string, claims map[string]string) (*RegistrationEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries WHERE attestor = ?`,
		attestorName,
	)
	if err != nil {
		return nil, fmt.Errorf("match query: %w", err)
	}
	defer rows.Close()

	var entries []*RegistrationEntry
	for rows.Next() {
		e, err := scanEntryRows(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	best := MatchEntries(entries, attestorName, claims)
	if best == nil {
		return nil, fmt.Errorf("no matching entry for attestor %q", attestorName)
	}
	return best, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
