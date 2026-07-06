package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RetestOutcome is the verdict of re-testing a finding (retest tracking).
type RetestOutcome string

const (
	RetestRemediated      RetestOutcome = "remediated"
	RetestStillVulnerable RetestOutcome = "still_vulnerable"
	RetestNotReproducible RetestOutcome = "not_reproducible"
)

// Valid reports whether o is a known outcome.
func (o RetestOutcome) Valid() bool {
	switch o {
	case RetestRemediated, RetestStillVulnerable, RetestNotReproducible:
		return true
	default:
		return false
	}
}

// ResultingStatus maps a retest outcome to the finding status it implies, so a
// retest moves the finding consistently (remediated -> remediated, still vulnerable
// -> confirmed, not reproducible -> false positive).
func (o RetestOutcome) ResultingStatus() Status {
	switch o {
	case RetestRemediated:
		return StatusRemediated
	case RetestStillVulnerable:
		return StatusConfirmed
	case RetestNotReproducible:
		return StatusFalsePos
	default:
		return ""
	}
}

// Retest is one append-only retest record on a finding (who re-tested, the outcome,
// and a note), kept as history for chain-of-custody and consultancy reporting.
type Retest struct {
	ID           shared.ID     `json:"id"`
	EngagementID shared.ID     `json:"engagementId"`
	FindingID    shared.ID     `json:"findingId"`
	Outcome      RetestOutcome `json:"outcome"`
	Note         string        `json:"note,omitempty"`
	Tester       string        `json:"tester"`
	At           time.Time     `json:"at"`
}

// NewRetest validates and constructs a retest record.
func NewRetest(id, engagementID, findingID shared.ID, outcome RetestOutcome, note, tester string, now time.Time) (Retest, error) {
	if !outcome.Valid() {
		return Retest{}, fmt.Errorf("%w: invalid retest outcome %q", shared.ErrValidation, outcome)
	}
	tester = strings.TrimSpace(tester)
	if tester == "" {
		return Retest{}, fmt.Errorf("%w: retest tester is required", shared.ErrValidation)
	}
	return Retest{
		ID:           id,
		EngagementID: engagementID,
		FindingID:    findingID,
		Outcome:      outcome,
		Note:         strings.TrimSpace(note),
		Tester:       tester,
		At:           now,
	}, nil
}
