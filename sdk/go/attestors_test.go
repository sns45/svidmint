package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudflareClientAttestor_EvidenceType(t *testing.T) {
	att := CloudflareClientAttestor("test-jwt")
	assert.Equal(t, "cloudflare_workers", att.EvidenceType())
}

func TestCloudflareClientAttestor_GatherEvidence(t *testing.T) {
	att := CloudflareClientAttestor("test-jwt")
	evidence, err := att.GatherEvidence(context.Background())
	require.NoError(t, err)
	assert.Contains(t, string(evidence), "access_jwt")
	assert.Contains(t, string(evidence), "test-jwt")
}

func TestCloudflareClientAttestor_ImplementsInterface(t *testing.T) {
	var _ ClientAttestor = CloudflareClientAttestor("jwt")
}

func TestGitHubOIDCClientAttestor_EvidenceType(t *testing.T) {
	att := GitHubOIDCClientAttestor("my-audience")
	assert.Equal(t, "github_oidc", att.EvidenceType())
}

func TestGitHubOIDCClientAttestor_MissingEnv(t *testing.T) {
	att := GitHubOIDCClientAttestor("aud")
	_, err := att.GatherEvidence(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestGitHubOIDCClientAttestor_ImplementsInterface(t *testing.T) {
	var _ ClientAttestor = GitHubOIDCClientAttestor("aud")
}

func TestGitHubOIDCClientAttestor_FetchesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "bearer test-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.RawQuery, "audience=my-aud")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"value":"fetched-oidc-token"}`)
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"?param=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	att := GitHubOIDCClientAttestor("my-aud")
	evidence, err := att.GatherEvidence(context.Background())
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(evidence, &parsed))
	assert.Equal(t, "fetched-oidc-token", parsed["oidc_token"])
}

func TestAWSLambdaClientAttestor_EvidenceType(t *testing.T) {
	att := AWSLambdaClientAttestor()
	assert.Equal(t, "aws_sts", att.EvidenceType())
}

func TestAWSLambdaClientAttestor_ImplementsInterface(t *testing.T) {
	var _ ClientAttestor = AWSLambdaClientAttestor()
}

func TestAWSLambdaClientAttestor_ReturnsNotImplemented(t *testing.T) {
	att := AWSLambdaClientAttestor()
	_, err := att.GatherEvidence(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}
