package entry

type RegistrationEntry struct {
	ID        string   `json:"id" yaml:"id"`
	SpiffeID  string   `json:"spiffe_id" yaml:"spiffe_id"`
	Attestor  string   `json:"attestor" yaml:"attestor"`
	Selectors []string `json:"selectors" yaml:"selectors"`
	TTL       int      `json:"ttl" yaml:"ttl"`
}
