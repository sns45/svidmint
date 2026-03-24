// Package mapper maps attestation results to SPIFFE IDs.
package mapper

import (
	"fmt"
	"sort"
	"strings"
)

// DeriveSpiffeID constructs a SPIFFE ID from a trust domain, attestor name,
// and a set of claims. Claim values are sorted by key to ensure deterministic output.
func DeriveSpiffeID(trustDomain, attestor string, claims map[string]string) string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, k := range keys {
		values = append(values, claims[k])
	}
	return fmt.Sprintf("spiffe://%s/%s/%s", trustDomain, attestor, strings.Join(values, "/"))
}
