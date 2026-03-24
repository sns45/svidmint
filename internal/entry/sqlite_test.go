package entry

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteStore_CRUD(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()

	entry := &RegistrationEntry{
		ID: "test-1", SpiffeID: "spiffe://example.org/a",
		Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}, TTL: 300,
	}
	require.NoError(t, store.Create(ctx, entry))

	got, err := store.Get(ctx, "test-1")
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/a", got.SpiffeID)
	assert.Equal(t, []string{"aws.account_id:123"}, got.Selectors)

	all, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	entry.TTL = 600
	require.NoError(t, store.Update(ctx, entry))
	got, _ = store.Get(ctx, "test-1")
	assert.Equal(t, 600, got.TTL)

	require.NoError(t, store.Delete(ctx, "test-1"))
	_, err = store.Get(ctx, "test-1")
	assert.Error(t, err)
}

func TestSQLiteStore_Match(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()

	store.Create(ctx, &RegistrationEntry{
		ID: "e1", SpiffeID: "spiffe://example.org/a",
		Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}, TTL: 300,
	})
	store.Create(ctx, &RegistrationEntry{
		ID: "e2", SpiffeID: "spiffe://example.org/b",
		Attestor: "aws_sts", Selectors: []string{"aws.account_id:123", "aws.function_name:api"}, TTL: 300,
	})

	result, err := store.Match(ctx, "aws_sts", map[string]string{"aws.account_id": "123", "aws.function_name": "api"})
	require.NoError(t, err)
	assert.Equal(t, "e2", result.ID)
}
