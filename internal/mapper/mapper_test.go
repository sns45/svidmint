package mapper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveSpiffeID(t *testing.T) {
	id := DeriveSpiffeID("example.org", "aws_sts", map[string]string{
		"aws.account_id":    "123",
		"aws.function_name": "api",
	})
	assert.Equal(t, "spiffe://example.org/aws_sts/123/api", id)
}

func TestDeriveSpiffeID_SingleClaim(t *testing.T) {
	id := DeriveSpiffeID("example.org", "github_oidc", map[string]string{
		"github.repository": "org/repo",
	})
	assert.Equal(t, "spiffe://example.org/github_oidc/org/repo", id)
}

func TestDeriveSpiffeID_SortedKeys(t *testing.T) {
	id := DeriveSpiffeID("example.org", "aws_sts", map[string]string{
		"z_claim": "zval",
		"a_claim": "aval",
	})
	assert.Equal(t, "spiffe://example.org/aws_sts/aval/zval", id)
}
