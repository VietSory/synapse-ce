//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RuntimeSensor is the non-Linux stub. Runtime reachability is raise-only, so unsupported platforms
// emit no evidence and return an explicit unavailable error rather than manufacturing a negative result.
type RuntimeSensor struct {
	events    chan detection.RuntimeEvidence
	closeOnce sync.Once
}

func NewRuntimeSensor(host shared.ID) (*RuntimeSensor, error) {
	if host.IsZero() {
		return nil, fmt.Errorf("%w: runtime sensor host id is required", shared.ErrValidation)
	}
	return &RuntimeSensor{events: make(chan detection.RuntimeEvidence)}, nil
}

func (s *RuntimeSensor) Start(_ context.Context) error { return ErrRuntimeSensorUnavailable }

func (s *RuntimeSensor) AttachSymbolProbe(ctx context.Context, _ RuntimeSymbolProbe) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: attach symbol probe: %v", ErrRuntimeSensorUnavailable, err)
	}
	return fmt.Errorf("%w: Linux only", ErrRuntimeSensorUnavailable)
}

func (s *RuntimeSensor) Events() <-chan detection.RuntimeEvidence { return s.events }

func (s *RuntimeSensor) Dropped() uint64 { return 0 }

func (s *RuntimeSensor) Close() error {
	s.closeOnce.Do(func() { close(s.events) })
	return nil
}
