package entry

import (
	"os"

	"gopkg.in/yaml.v3"
)

// LoadEntriesFromFile reads a YAML file containing registration entries and
// returns the parsed slice.
func LoadEntriesFromFile(path string) ([]*RegistrationEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Entries []*RegistrationEntry `yaml:"entries"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Entries, nil
}
