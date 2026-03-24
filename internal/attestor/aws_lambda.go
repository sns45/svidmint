package attestor

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var stsEndpointPattern = regexp.MustCompile(`^https://sts(\.[a-z0-9-]+)?\.amazonaws\.com/$`)

// AWSLambdaAttestorConfig holds configuration for the AWS Lambda attestor.
type AWSLambdaAttestorConfig struct {
	AllowedAccountIDs   []string
	AllowedRegions      []string
	STSEndpointOverride string // testing only
}

// AWSLambdaAttestor validates AWS caller identity via pre-signed STS requests.
type AWSLambdaAttestor struct {
	config     AWSLambdaAttestorConfig
	httpClient *http.Client
}

type stsEvidence struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Headers string `json:"headers"`
	Body    string `json:"body"`
}

type getCallerIdentityResponse struct {
	XMLName xml.Name                  `xml:"GetCallerIdentityResponse"`
	Result  getCallerIdentityResult   `xml:"GetCallerIdentityResult"`
}

type getCallerIdentityResult struct {
	Account string `xml:"Account"`
	Arn     string `xml:"Arn"`
	UserID  string `xml:"UserId"`
}

// NewAWSLambdaAttestor creates a new AWS Lambda attestor with the given config.
func NewAWSLambdaAttestor(cfg AWSLambdaAttestorConfig) *AWSLambdaAttestor {
	return &AWSLambdaAttestor{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns the attestor name.
func (a *AWSLambdaAttestor) Name() string {
	return "aws_sts"
}

// CanAttest returns true if the evidence type matches this attestor.
func (a *AWSLambdaAttestor) CanAttest(evidenceType string) bool {
	return evidenceType == "aws_sts"
}

// Attest validates AWS STS pre-signed request evidence and returns attestation claims.
func (a *AWSLambdaAttestor) Attest(ctx context.Context, evidence []byte) (*AttestationResult, error) {
	var ev stsEvidence
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, fmt.Errorf("failed to parse evidence JSON: %w", err)
	}

	var headers map[string]string
	if err := json.Unmarshal([]byte(ev.Headers), &headers); err != nil {
		return nil, fmt.Errorf("failed to parse headers JSON: %w", err)
	}

	// SSRF prevention: validate the STS endpoint URL
	if err := a.validateEndpoint(ev.URL); err != nil {
		return nil, err
	}

	// Timestamp validation
	amzDate, ok := headers["X-Amz-Date"]
	if !ok {
		return nil, fmt.Errorf("missing X-Amz-Date header")
	}
	ts, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return nil, fmt.Errorf("invalid X-Amz-Date format: %w", err)
	}
	now := time.Now().UTC()
	if now.Sub(ts) > 5*time.Minute {
		return nil, fmt.Errorf("timestamp too old: X-Amz-Date is more than 5 minutes in the past")
	}
	if ts.Sub(now) > 1*time.Minute {
		return nil, fmt.Errorf("timestamp too far in the future: X-Amz-Date is more than 1 minute ahead")
	}

	// Reconstruct and send HTTP request to STS
	req, err := http.NewRequestWithContext(ctx, ev.Method, ev.URL, strings.NewReader(ev.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create STS request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read STS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STS returned non-200 status %d: %s", resp.StatusCode, string(body))
	}

	var stsResp getCallerIdentityResponse
	if err := xml.Unmarshal(body, &stsResp); err != nil {
		return nil, fmt.Errorf("failed to parse STS XML response: %w", err)
	}

	account := stsResp.Result.Account
	arn := stsResp.Result.Arn

	// Account validation
	if len(a.config.AllowedAccountIDs) > 0 {
		allowed := false
		for _, id := range a.config.AllowedAccountIDs {
			if id == account {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("account %s is not in the allowed account list", account)
		}
	}

	// Extract region and function name from ARN
	// ARN format: arn:aws:lambda:<region>:<account>:function:<name>
	region, functionName := parseARN(arn)

	claims := map[string]string{
		"aws.account_id":   account,
		"aws.arn":          arn,
		"aws.region":       region,
		"aws.function_name": functionName,
	}

	return &AttestationResult{
		Claims:      claims,
		ExpiresAt:   ts.Add(1 * time.Hour),
		RawIdentity: arn,
	}, nil
}

func (a *AWSLambdaAttestor) validateEndpoint(url string) error {
	if a.config.STSEndpointOverride != "" {
		if strings.HasPrefix(url, a.config.STSEndpointOverride) {
			return nil
		}
		return fmt.Errorf("SSRF prevention: URL %q does not match endpoint override %q", url, a.config.STSEndpointOverride)
	}
	if !stsEndpointPattern.MatchString(url) {
		return fmt.Errorf("SSRF prevention: URL %q does not match allowed STS endpoint pattern", url)
	}
	return nil
}

func parseARN(arn string) (region, functionName string) {
	// arn:aws:lambda:us-east-1:123456789012:function:my-api
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		region = parts[3]
	}
	if len(parts) >= 7 && parts[5] == "function" {
		functionName = parts[6]
	}
	return region, functionName
}
