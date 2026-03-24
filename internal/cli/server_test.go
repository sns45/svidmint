package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerStartCommand_HasExpectedFlags(t *testing.T) {
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"server", "start", "--help"})
	err := cmd.Execute()
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "--config")
	assert.Contains(t, output, "--listen")
	assert.Contains(t, output, "--trust-domain")
	assert.Contains(t, output, "--entries")
}

func TestServerConfigCommand(t *testing.T) {
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"server", "config"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "trustdomain")
}
