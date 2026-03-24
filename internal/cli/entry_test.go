package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntryCreateAndList(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"entry", "create",
		"--db", dbPath,
		"--spiffe-id", "spiffe://example.org/api",
		"--attestor", "aws_sts",
		"--selector", "aws.account_id:123",
		"--selector", "aws.function_name:api",
		"--ttl", "300",
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	// List
	cmd2 := newRootCmd()
	buf := new(bytes.Buffer)
	cmd2.SetOut(buf)
	cmd2.SetArgs([]string{"entry", "list", "--db", dbPath})
	err = cmd2.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "spiffe://example.org/api")
}

func TestEntryCreateInvalidSpiffeID(t *testing.T) {
	dir := t.TempDir()
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"entry", "create",
		"--db", filepath.Join(dir, "test.db"),
		"--spiffe-id", "not-a-spiffe-id",
		"--attestor", "aws_sts",
		"--selector", "aws.account_id:123",
	})
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestEntryShowAndDelete(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create with explicit ID
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"entry", "create",
		"--db", dbPath,
		"--id", "entry-001",
		"--spiffe-id", "spiffe://example.org/svc",
		"--attestor", "aws_sts",
		"--selector", "aws.account_id:456",
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	// Show
	cmd2 := newRootCmd()
	buf := new(bytes.Buffer)
	cmd2.SetOut(buf)
	cmd2.SetArgs([]string{"entry", "show", "--db", dbPath, "--id", "entry-001"})
	err = cmd2.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "spiffe://example.org/svc")

	// Delete
	cmd3 := newRootCmd()
	cmd3.SetArgs([]string{"entry", "delete", "--db", dbPath, "--id", "entry-001"})
	err = cmd3.Execute()
	assert.NoError(t, err)

	// Show after delete should fail
	cmd4 := newRootCmd()
	cmd4.SetArgs([]string{"entry", "show", "--db", dbPath, "--id", "entry-001"})
	err = cmd4.Execute()
	assert.Error(t, err)
}

func TestEntryUpdate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"entry", "create",
		"--db", dbPath,
		"--id", "entry-upd",
		"--spiffe-id", "spiffe://example.org/old",
		"--attestor", "aws_sts",
		"--selector", "aws.account_id:789",
		"--ttl", "100",
	})
	assert.NoError(t, cmd.Execute())

	// Update TTL
	cmd2 := newRootCmd()
	cmd2.SetArgs([]string{
		"entry", "update",
		"--db", dbPath,
		"--id", "entry-upd",
		"--ttl", "600",
	})
	assert.NoError(t, cmd2.Execute())

	// Show updated
	cmd3 := newRootCmd()
	buf := new(bytes.Buffer)
	cmd3.SetOut(buf)
	cmd3.SetArgs([]string{"entry", "show", "--db", dbPath, "--id", "entry-upd"})
	assert.NoError(t, cmd3.Execute())
	assert.Contains(t, buf.String(), "600")
}

func TestEntryListByAttestor(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create two entries with different attestors
	for _, args := range [][]string{
		{"entry", "create", "--db", dbPath, "--spiffe-id", "spiffe://example.org/a", "--attestor", "aws_sts", "--selector", "k:v"},
		{"entry", "create", "--db", dbPath, "--spiffe-id", "spiffe://example.org/b", "--attestor", "gcp_iit", "--selector", "k:v"},
	} {
		cmd := newRootCmd()
		cmd.SetArgs(args)
		assert.NoError(t, cmd.Execute())
	}

	// List filtering by attestor
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"entry", "list", "--db", dbPath, "--attestor", "aws_sts"})
	assert.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "spiffe://example.org/a")
	assert.NotContains(t, buf.String(), "spiffe://example.org/b")
}
