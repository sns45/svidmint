package attestor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAttestor is a simple mock implementing the Attestor interface.
type mockAttestor struct {
	name         string
	evidenceType string
	result       *AttestationResult
	err          error
}

func (m *mockAttestor) Name() string {
	return m.name
}

func (m *mockAttestor) CanAttest(evidenceType string) bool {
	return evidenceType == m.evidenceType
}

func (m *mockAttestor) Attest(_ context.Context, _ []byte) (*AttestationResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestRegistry_RoutesToCorrectAttestor(t *testing.T) {
	awsMock := &mockAttestor{
		name:         "aws_sts",
		evidenceType: "aws_sts",
		result: &AttestationResult{
			Claims:      map[string]string{"provider": "aws"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			RawIdentity: "aws-identity",
		},
	}
	denoMock := &mockAttestor{
		name:         "deno_oidc",
		evidenceType: "deno_oidc",
		result: &AttestationResult{
			Claims:      map[string]string{"provider": "deno"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			RawIdentity: "deno-identity",
		},
	}

	registry := NewRegistry(awsMock, denoMock)

	result, err := registry.Attest(context.Background(), "deno_oidc", []byte("evidence"))
	require.NoError(t, err)
	assert.Equal(t, "deno", result.Claims["provider"])
	assert.Equal(t, "deno-identity", result.RawIdentity)

	result, err = registry.Attest(context.Background(), "aws_sts", []byte("evidence"))
	require.NoError(t, err)
	assert.Equal(t, "aws", result.Claims["provider"])
	assert.Equal(t, "aws-identity", result.RawIdentity)
}

func TestRegistry_NoMatchingAttestor(t *testing.T) {
	awsMock := &mockAttestor{
		name:         "aws_sts",
		evidenceType: "aws_sts",
	}

	registry := NewRegistry(awsMock)

	_, err := registry.Attest(context.Background(), "unknown_type", []byte("evidence"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no attestor found")
	assert.Contains(t, err.Error(), "unknown_type")
}

func TestRegistry_EmptyRegistry(t *testing.T) {
	registry := NewRegistry()

	_, err := registry.Attest(context.Background(), "aws_sts", []byte("evidence"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no attestor found")
}

func TestRegistry_AttestorError(t *testing.T) {
	failMock := &mockAttestor{
		name:         "fail",
		evidenceType: "fail_type",
		err:          fmt.Errorf("attestation failed"),
	}

	registry := NewRegistry(failMock)

	_, err := registry.Attest(context.Background(), "fail_type", []byte("evidence"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation failed")
}

func TestRegistry_FirstMatchWins(t *testing.T) {
	first := &mockAttestor{
		name:         "first",
		evidenceType: "shared_type",
		result: &AttestationResult{
			Claims:      map[string]string{"which": "first"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			RawIdentity: "first",
		},
	}
	second := &mockAttestor{
		name:         "second",
		evidenceType: "shared_type",
		result: &AttestationResult{
			Claims:      map[string]string{"which": "second"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			RawIdentity: "second",
		},
	}

	registry := NewRegistry(first, second)

	result, err := registry.Attest(context.Background(), "shared_type", []byte("evidence"))
	require.NoError(t, err)
	assert.Equal(t, "first", result.Claims["which"])
}
