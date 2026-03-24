package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand_HasExpectedSubcommands(t *testing.T) {
	cmd := newRootCmd()
	subcommands := make(map[string]bool)
	for _, c := range cmd.Commands() {
		subcommands[c.Name()] = true
	}
	for _, name := range []string{"server", "entry", "bundle", "token", "ca", "version"} {
		assert.True(t, subcommands[name], "missing subcommand: %s", name)
	}
}

func TestRootCommand_PersistentFlags(t *testing.T) {
	cmd := newRootCmd()
	flags := cmd.PersistentFlags()

	configFlag := flags.Lookup("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, ".svidmint.yaml", configFlag.DefValue)

	logLevel := flags.Lookup("log-level")
	require.NotNil(t, logLevel)
	assert.Equal(t, "info", logLevel.DefValue)

	logFormat := flags.Lookup("log-format")
	require.NotNil(t, logFormat)
	assert.Equal(t, "json", logFormat.DefValue)
}
