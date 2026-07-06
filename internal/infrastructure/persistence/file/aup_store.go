// Package file provides simple file-backed stores for single-tenant self-host
// mode and tests. Replaced by the Postgres adapters.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AUPStore persists AUP acceptances as a JSON file keyed by version. This holds
// current state; the immutable history lives in the append-only audit log.
type AUPStore struct {
	path string
	mu   sync.Mutex
}

// NewAUPStore returns a store backed by the JSON file at path.
func NewAUPStore(path string) *AUPStore { return &AUPStore{path: path} }

var _ ports.AUPStore = (*AUPStore)(nil)

// Accepted reports whether the given version has an acceptance record.
func (s *AUPStore) Accepted(ctx context.Context, version string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return false, err
	}
	_, ok := m[version]
	return ok, nil
}

// Save records an acceptance, replacing any prior current-state record for that
// version (history is preserved by the audit log, not here).
func (s *AUPStore) Save(ctx context.Context, a aup.Acceptance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	m[a.Version] = a
	return s.store(m)
}

func (s *AUPStore) load() (map[string]aup.Acceptance, error) {
	b, err := os.ReadFile(s.path) // #nosec G304 -- path is operator config, not request input
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]aup.Acceptance{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("aup store load: %w", err)
	}
	m := map[string]aup.Acceptance{}
	if len(b) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("aup store decode: %w", err)
	}
	return m, nil
}

func (s *AUPStore) store(m map[string]aup.Acceptance) error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("aup store mkdir: %w", err)
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("aup store encode: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("aup store write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil { // atomic replace
		_ = os.Remove(tmp)
		return fmt.Errorf("aup store rename: %w", err)
	}
	return nil
}
