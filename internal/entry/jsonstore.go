package entry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// JSONStore implements Store using a JSON file for persistence.
// This serves as a lightweight store for CLI usage until the SQLite
// store is available.
type JSONStore struct {
	path    string
	mu      sync.Mutex
	entries map[string]*RegistrationEntry
}

// NewJSONStore opens or creates a JSON file backed store at path.
func NewJSONStore(path string) (*JSONStore, error) {
	s := &JSONStore{
		path:    path,
		entries: make(map[string]*RegistrationEntry),
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.entries); err != nil {
			return nil, fmt.Errorf("corrupt store file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *JSONStore) save() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *JSONStore) Create(_ context.Context, e *RegistrationEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[e.ID]; exists {
		return fmt.Errorf("entry %s already exists", e.ID)
	}
	s.entries[e.ID] = e
	return s.save()
}

func (s *JSONStore) Get(_ context.Context, id string) (*RegistrationEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, fmt.Errorf("entry %s not found", id)
	}
	return e, nil
}

func (s *JSONStore) List(_ context.Context) ([]*RegistrationEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*RegistrationEntry, 0, len(s.entries))
	for _, e := range s.entries {
		result = append(result, e)
	}
	return result, nil
}

func (s *JSONStore) Update(_ context.Context, e *RegistrationEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[e.ID]; !exists {
		return fmt.Errorf("entry %s not found", e.ID)
	}
	s.entries[e.ID] = e
	return s.save()
}

func (s *JSONStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[id]; !exists {
		return fmt.Errorf("entry %s not found", id)
	}
	delete(s.entries, id)
	return s.save()
}

func (s *JSONStore) Match(_ context.Context, attestorName string, claims map[string]string) (*RegistrationEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.Attestor != attestorName {
			continue
		}
		selectorMap := make(map[string]bool)
		for _, sel := range e.Selectors {
			selectorMap[sel] = true
		}
		allMatch := true
		for k, v := range claims {
			if !selectorMap[k+":"+v] {
				allMatch = false
				break
			}
		}
		if allMatch {
			return e, nil
		}
	}
	return nil, fmt.Errorf("no matching entry found")
}

func (s *JSONStore) Close() error {
	return nil
}
