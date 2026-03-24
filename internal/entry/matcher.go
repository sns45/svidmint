package entry

import (
	"path"
	"strings"
)

// MatchEntries finds the best matching registration entry for the given attestor
// and claims. All selectors on an entry must match (AND semantics). Selector
// values support glob patterns via path.Match. When multiple entries match, the
// one with the most selectors wins; ties are broken by lexicographic ID order.
func MatchEntries(entries []*RegistrationEntry, attestorName string, claims map[string]string) *RegistrationEntry {
	var best *RegistrationEntry
	for _, e := range entries {
		if e.Attestor != attestorName {
			continue
		}
		if !allSelectorsMatch(e.Selectors, claims) {
			continue
		}
		if best == nil || len(e.Selectors) > len(best.Selectors) ||
			(len(e.Selectors) == len(best.Selectors) && e.ID < best.ID) {
			best = e
		}
	}
	return best
}

func allSelectorsMatch(selectors []string, claims map[string]string) bool {
	for _, sel := range selectors {
		k, v, ok := strings.Cut(sel, ":")
		if !ok {
			return false
		}
		claimVal, exists := claims[k]
		if !exists {
			return false
		}
		matched, err := path.Match(v, claimVal)
		if err != nil || !matched {
			return false
		}
	}
	return true
}
