package fleetagent

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestHighestContiguousDurableOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		delivered []uint64
		losses    []SeqRange
		want      uint64
	}{
		{name: "delivered only", delivered: []uint64{3, 1, 2}, want: 3},
		{name: "known loss bridges prefix", delivered: []uint64{3}, losses: []SeqRange{{From: 1, To: 2}}, want: 3},
		{name: "known loss bridges middle", delivered: []uint64{1, 4}, losses: []SeqRange{{From: 2, To: 3}}, want: 4},
		{name: "later evidence cannot bridge first hole", delivered: []uint64{3}, losses: []SeqRange{{From: 2, To: 2}}, want: 0},
		{name: "overlapping evidence is harmless", delivered: []uint64{1, 3}, losses: []SeqRange{{From: 1, To: 2}, {From: 2, To: 4}}, want: 4},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HighestContiguousDurableOutcome(tt.delivered, tt.losses)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("ACK=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestHighestContiguousDurableOutcomeRejectsInvalidCoordinates(t *testing.T) {
	t.Parallel()
	if _, err := HighestContiguousDurableOutcome([]uint64{0}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero delivered sequence error=%v, want validation", err)
	}
	if _, err := HighestContiguousDurableOutcome(nil, []SeqRange{{From: 3, To: 2}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid loss range error=%v, want validation", err)
	}
}
