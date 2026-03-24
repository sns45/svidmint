package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionCommand_Output(t *testing.T) {
	SetVersionInfo("0.1.0", "abc1234", "2026-03-17T00:00:00Z")
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "svidmint version 0.1.0")
	assert.Contains(t, buf.String(), "abc1234")
	assert.Contains(t, buf.String(), "2026-03-17T00:00:00Z")
}
