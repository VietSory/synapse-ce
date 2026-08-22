package fleetagent

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// HighestContiguousDurableOutcome returns the highest sequence for which every
// coordinate from one through the result has a durable server-side outcome. An
// outcome is either an ingested telemetry event or an explicitly persisted,
// known-coordinate loss range. Unknown-coordinate loss must never be supplied
// here because it cannot prove which sequence can safely be skipped.
func HighestContiguousDurableOutcome(delivered []uint64, durableLoss []SeqRange) (uint64, error) {
	type interval struct {
		from uint64
		to   uint64
	}
	intervals := make([]interval, 0, len(delivered)+len(durableLoss))
	for _, sequence := range delivered {
		if sequence == 0 {
			return 0, fmt.Errorf("%w: durable delivery sequence must be positive", shared.ErrValidation)
		}
		intervals = append(intervals, interval{from: sequence, to: sequence})
	}
	for _, loss := range durableLoss {
		if loss.From == 0 || loss.To < loss.From {
			return 0, fmt.Errorf("%w: durable loss range %d..%d is invalid", shared.ErrValidation, loss.From, loss.To)
		}
		intervals = append(intervals, interval{from: loss.From, to: loss.To})
	}
	if len(intervals) == 0 {
		return 0, nil
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].from == intervals[j].from {
			return intervals[i].to < intervals[j].to
		}
		return intervals[i].from < intervals[j].from
	})

	var through uint64
	for _, current := range intervals {
		if current.from > through+1 {
			break
		}
		if current.to > through {
			through = current.to
		}
	}
	return through, nil
}
