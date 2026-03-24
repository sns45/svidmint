package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stsValidResponse = `<GetCallerIdentityResponse>
  <GetCallerIdentityResult>
    <Account>123456789012</Account>
    <Arn>arn:aws:lambda:us-east-1:123456789012:function:my-api</Arn>
    <UserId>AROA12345:my-api</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

func makeEvidence(t *testing.T, method, url string, headers map[string]string, body string) []byte {
	t.Helper()
	headersJSON, err := json.Marshal(headers)
	require.NoError(t, err)
	ev := map[string]string{
		"method":  method,
		"url":     url,
		"headers": string(headersJSON),
		"body":    body,
	}
	data, err := json.Marshal(ev)
	require.NoError(t, err)
	return data
}

func TestAWSLambdaAttestor_Valid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, stsValidResponse)
	}))
	defer srv.Close()

	attestor := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{
		AllowedAccountIDs:   []string{"123456789012"},
		STSEndpointOverride: srv.URL + "/",
	})
	attestor.httpClient = srv.Client()

	now := time.Now().UTC().Format("20060102T150405Z")
	evidence := makeEvidence(t, "POST", srv.URL+"/", map[string]string{
		"X-Amz-Date": now,
	}, "Action=GetCallerIdentity&Version=2011-06-15")

	result, err := attestor.Attest(context.Background(), evidence)
	require.NoError(t, err)
	assert.Equal(t, "123456789012", result.Claims["aws.account_id"])
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:my-api", result.Claims["aws.arn"])
	assert.Equal(t, "us-east-1", result.Claims["aws.region"])
	assert.Equal(t, "my-api", result.Claims["aws.function_name"])
	assert.False(t, result.ExpiresAt.IsZero())
}

func TestAWSLambdaAttestor_ExpiredTimestamp(t *testing.T) {
	attestor := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{
		STSEndpointOverride: "https://sts.amazonaws.com/",
	})

	expired := time.Now().UTC().Add(-10 * time.Minute).Format("20060102T150405Z")
	evidence := makeEvidence(t, "POST", "https://sts.amazonaws.com/", map[string]string{
		"X-Amz-Date": expired,
	}, "Action=GetCallerIdentity&Version=2011-06-15")

	_, err := attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp")
}

func TestAWSLambdaAttestor_InvalidSTSEndpoint(t *testing.T) {
	attestor := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{})

	now := time.Now().UTC().Format("20060102T150405Z")
	evidence := makeEvidence(t, "POST", "https://evil.example.com/", map[string]string{
		"X-Amz-Date": now,
	}, "Action=GetCallerIdentity&Version=2011-06-15")

	_, err := attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF")
}

func TestAWSLambdaAttestor_DisallowedAccount(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, stsValidResponse)
	}))
	defer srv.Close()

	attestor := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{
		AllowedAccountIDs:   []string{"999999999999"},
		STSEndpointOverride: srv.URL + "/",
	})
	attestor.httpClient = srv.Client()

	now := time.Now().UTC().Format("20060102T150405Z")
	evidence := makeEvidence(t, "POST", srv.URL+"/", map[string]string{
		"X-Amz-Date": now,
	}, "Action=GetCallerIdentity&Version=2011-06-15")

	_, err := attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account")
}

func TestAWSLambdaAttestor_STSError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
	}))
	defer srv.Close()

	attestor := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{
		STSEndpointOverride: srv.URL + "/",
	})
	attestor.httpClient = srv.Client()

	now := time.Now().UTC().Format("20060102T150405Z")
	evidence := makeEvidence(t, "POST", srv.URL+"/", map[string]string{
		"X-Amz-Date": now,
	}, "Action=GetCallerIdentity&Version=2011-06-15")

	_, err := attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STS")
}

func TestAWSLambdaAttestor_NameAndCanAttest(t *testing.T) {
	a := NewAWSLambdaAttestor(AWSLambdaAttestorConfig{})
	assert.Equal(t, "aws_sts", a.Name())
	assert.True(t, a.CanAttest("aws_sts"))
	assert.False(t, a.CanAttest("gcp"))
}
