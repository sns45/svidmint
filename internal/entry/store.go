package entry

import "context"

type Store interface {
	Create(ctx context.Context, entry *RegistrationEntry) error
	Get(ctx context.Context, id string) (*RegistrationEntry, error)
	List(ctx context.Context) ([]*RegistrationEntry, error)
	Update(ctx context.Context, entry *RegistrationEntry) error
	Delete(ctx context.Context, id string) error
	Match(ctx context.Context, attestorName string, claims map[string]string) (*RegistrationEntry, error)
	Close() error
}
