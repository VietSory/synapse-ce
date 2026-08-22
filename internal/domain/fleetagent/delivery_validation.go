package fleetagent

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Validate returns a validation error when p is outside the delivery priority
// ladder. It complements Valid for callers that need a composable error path.
func (p DeliveryPriority) Validate() error {
	if !p.Valid() {
		return fmt.Errorf("%w: unknown delivery priority %d", shared.ErrValidation, int(p))
	}
	return nil
}
