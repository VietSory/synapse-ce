//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

type SymbolHitSensor struct {
	events chan detection.RuntimeEvidence
	once   sync.Once
}

func NewSymbolHitSensor(raw RuntimeSymbolProbe) (*SymbolHitSensor, error) {
	if _, err := raw.validate(); err != nil {
		return nil, err
	}
	return &SymbolHitSensor{events: make(chan detection.RuntimeEvidence)}, nil
}

func (s *SymbolHitSensor) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrSymbolHitUnavailable, err)
	}
	return fmt.Errorf("%w: Linux only", ErrSymbolHitUnavailable)
}

func (s *SymbolHitSensor) Events() <-chan detection.RuntimeEvidence { return s.events }
func (s *SymbolHitSensor) Close() error {
	s.once.Do(func() { close(s.events) })
	return nil
}
