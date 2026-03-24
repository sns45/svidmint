package entry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
)

// Compile-time interface check.
var _ Store = (*PostgresStore)(nil)

// PostgresStore implements Store backed by a PostgreSQL database.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a PostgreSQL connection and ensures the schema exists.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS registration_entries (
		id TEXT PRIMARY KEY,
		spiffe_id TEXT NOT NULL,
		attestor TEXT NOT NULL,
		selectors TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 300,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return nil, fmt.Errorf("postgres create table: %w", err)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_entries_attestor ON registration_entries(attestor)`)
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Create(ctx context.Context, entry *RegistrationEntry) error {
	selJSON, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("marshal selectors: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO registration_entries (id, spiffe_id, attestor, selectors, ttl) VALUES ($1, $2, $3, $4, $5)`,
		entry.ID, entry.SpiffeID, entry.Attestor, string(selJSON), entry.TTL,
	)
	if err != nil {
		return fmt.Errorf("postgres create: %w", err)
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*RegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries WHERE id = $1`, id,
	)
	return scanEntry(row) // shared helper in sqlite.go
}

func (s *PostgresStore) List(ctx context.Context) ([]*RegistrationEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres list: %w", err)
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

func (s *PostgresStore) Update(ctx context.Context, entry *RegistrationEntry) error {
	selJSON, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("marshal selectors: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE registration_entries SET spiffe_id = $1, attestor = $2, selectors = $3, ttl = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5`,
		entry.SpiffeID, entry.Attestor, string(selJSON), entry.TTL, entry.ID,
	)
	if err != nil {
		return fmt.Errorf("postgres update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("entry not found: %s", entry.ID)
	}
	return nil
}

func (s *PostgresStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM registration_entries WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("postgres delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("entry not found: %s", id)
	}
	return nil
}

func (s *PostgresStore) Match(ctx context.Context, attestorName string, claims map[string]string) (*RegistrationEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, spiffe_id, attestor, selectors, ttl FROM registration_entries WHERE attestor = $1`, attestorName,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres match query: %w", err)
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
	return MatchEntries(entries, attestorName, claims), nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}
