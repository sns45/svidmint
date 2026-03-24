package entry

import "testing"

// Compile-time interface check.
var _ Store = (*PostgresStore)(nil)

func TestPostgresStore_ImplementsStoreInterface(t *testing.T) {
	t.Log("PostgresStore implements Store interface")
}
