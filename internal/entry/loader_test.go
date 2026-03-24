package entry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEntriesFromFile(t *testing.T) {
	yamlContent := `entries:
  - id: test-1
    spiffe_id: spiffe://example.org/api
    attestor: aws_sts
    selectors:
      - "aws.account_id:123456789012"
      - "aws.function_name:my-api"
    ttl: 300
  - id: test-2
    spiffe_id: spiffe://example.org/worker
    attestor: cloudflare_workers
    selectors:
      - "cf.team:myteam"
    ttl: 600
`
	f := filepath.Join(t.TempDir(), "entries.yaml")
	os.WriteFile(f, []byte(yamlContent), 0644)

	entries, err := LoadEntriesFromFile(f)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "spiffe://example.org/api", entries[0].SpiffeID)
	assert.Equal(t, "aws_sts", entries[0].Attestor)
	assert.Len(t, entries[0].Selectors, 2)
	assert.Equal(t, 300, entries[0].TTL)
}

func TestLoadEntriesFromFile_InvalidFile(t *testing.T) {
	_, err := LoadEntriesFromFile("/nonexistent/path.yaml")
	assert.Error(t, err)
}
