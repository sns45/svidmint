package entry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatch_ExactMatch(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "e1", SpiffeID: "spiffe://example.org/a", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}},
	}
	result := MatchEntries(entries, "aws_sts", map[string]string{"aws.account_id": "123"})
	require.NotNil(t, result)
	assert.Equal(t, "e1", result.ID)
}

func TestMatch_GlobPattern(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "e1", SpiffeID: "spiffe://example.org/a", Attestor: "github_oidc", Selectors: []string{"github.repository:org/*"}},
	}
	result := MatchEntries(entries, "github_oidc", map[string]string{"github.repository": "org/myrepo"})
	require.NotNil(t, result)
}

func TestMatch_AllSelectorsMustMatch(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "e1", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123", "aws.region:us-east-1"}},
	}
	result := MatchEntries(entries, "aws_sts", map[string]string{"aws.account_id": "123"})
	assert.Nil(t, result)
}

func TestMatch_MostSpecificWins(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "e1", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}, SpiffeID: "spiffe://example.org/general"},
		{ID: "e2", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123", "aws.function_name:api"}, SpiffeID: "spiffe://example.org/specific"},
	}
	result := MatchEntries(entries, "aws_sts", map[string]string{"aws.account_id": "123", "aws.function_name": "api"})
	require.NotNil(t, result)
	assert.Equal(t, "e2", result.ID)
}

func TestMatch_WrongAttestor(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "e1", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}},
	}
	result := MatchEntries(entries, "github_oidc", map[string]string{"aws.account_id": "123"})
	assert.Nil(t, result)
}

func TestMatch_NoEntries(t *testing.T) {
	result := MatchEntries(nil, "aws_sts", map[string]string{"aws.account_id": "123"})
	assert.Nil(t, result)
}

func TestMatch_TiesBrokenByID(t *testing.T) {
	entries := []*RegistrationEntry{
		{ID: "b", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}},
		{ID: "a", Attestor: "aws_sts", Selectors: []string{"aws.account_id:123"}},
	}
	result := MatchEntries(entries, "aws_sts", map[string]string{"aws.account_id": "123"})
	require.NotNil(t, result)
	assert.Equal(t, "a", result.ID)
}
