package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAInitCommand(t *testing.T) {
	dir := t.TempDir()
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, "root.key"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "root.crt"))
	assert.NoError(t, err)
}

func TestCAInitCommand_FailsIfExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.key"), []byte("existing"), 0600))

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestCAInitCommand_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.key"), []byte("existing"), 0600))

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
		"--force",
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, "root.crt"))
	assert.NoError(t, err)
}

func TestCAExportCommand(t *testing.T) {
	dir := t.TempDir()
	// First init
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	// Then export
	cmd2 := newRootCmd()
	buf := new(bytes.Buffer)
	cmd2.SetOut(buf)
	cmd2.SetArgs([]string{
		"ca", "export",
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err = cmd2.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "BEGIN CERTIFICATE")
}

func TestCARotateCommand(t *testing.T) {
	dir := t.TempDir()
	// First init
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err := cmd.Execute()
	assert.NoError(t, err)

	// Then rotate
	cmd2 := newRootCmd()
	cmd2.SetArgs([]string{
		"ca", "rotate",
		"--trust-domain", "test.org",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err = cmd2.Execute()
	assert.NoError(t, err)
}

func TestCAInitCommand_MissingTrustDomain(t *testing.T) {
	dir := t.TempDir()
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"ca", "init",
		"--root-key-path", filepath.Join(dir, "root.key"),
		"--root-cert-path", filepath.Join(dir, "root.crt"),
	})
	err := cmd.Execute()
	assert.Error(t, err)
}
