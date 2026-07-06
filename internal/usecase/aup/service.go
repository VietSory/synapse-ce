// Package aup (use case) implements first-run Acceptable-Use-Policy logic.
package aup

import (
	"context"
	"fmt"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service implements AUP use cases for a single current policy version.
type Service struct {
	store   ports.AUPStore
	audit   ports.AuditLogger
	clock   ports.Clock
	version string
}

// NewService wires the AUP use case.
func NewService(store ports.AUPStore, audit ports.AuditLogger, clock ports.Clock, version string) *Service {
	return &Service{store: store, audit: audit, clock: clock, version: version}
}

// Status reports the current version and whether it has been accepted.
type Status struct {
	Version  string `json:"version"`
	Accepted bool   `json:"accepted"`
}

// CurrentVersion returns the configured current AUP version.
func (s *Service) CurrentVersion() string { return s.version }

// IsAccepted reports whether the current version has been accepted.
func (s *Service) IsAccepted(ctx context.Context) (bool, error) {
	return s.store.Accepted(ctx, s.version)
}

// Status returns the current version + acceptance state.
func (s *Service) Status(ctx context.Context) (Status, error) {
	ok, err := s.IsAccepted(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{Version: s.version, Accepted: ok}, nil
}

// Accept records acceptance of the current version by actor, then writes an
// append-only audit entry. The submitted version
// must match the current one (avoids accepting a stale policy).
func (s *Service) Accept(ctx context.Context, actor, version string) error {
	if strings.TrimSpace(version) != s.version {
		return fmt.Errorf("%w: AUP version %q is not the current version %q", shared.ErrValidation, version, s.version)
	}
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	now := s.clock.Now()
	if err := s.store.Save(ctx, domain.Acceptance{Version: s.version, Actor: actor, AcceptedAt: now}); err != nil {
		return fmt.Errorf("save aup acceptance: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "aup.accept",
		Target:   "aup:" + s.version,
		Metadata: map[string]string{"version": s.version},
		At:       now,
	}); err != nil {
		return fmt.Errorf("audit aup acceptance: %w", err)
	}
	return nil
}
