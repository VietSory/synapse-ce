// Package fleetdesired defines the control-plane-owned desired state for fleet agents.
//
// Desired state is deliberately separate from fleetagent.Agent.Capabilities. Capabilities are an
// OBSERVATION reported by an untrusted agent; desired capabilities are an operator decision. Folding
// the two together would let an agent make a missing sensor disappear simply by ceasing to advertise
// it, which is the exact silent-coverage failure this package exists to prevent.
package fleetdesired

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// MaxCapabilities bounds one desired-state document. A fleet profile is a small set of sensor /
	// inventory classes; an unbounded list would turn an operator mutation into unbounded work on
	// every reconciliation read.
	MaxCapabilities = 64
	// MaxCapabilityLen bounds one capability identifier while leaving room for namespaced values.
	MaxCapabilityLen = 128
)

// State is the operator-owned desired capability set for one canonical AgentID. It is current state,
// not history: the append-only audit log records who changed it and when.
type State struct {
	TenantID     shared.ID
	AgentID      shared.ID
	Capabilities []string
	UpdatedBy    shared.ID
	Audit        shared.Audit
}

// GapReason explains why one desired capability is not currently covered.
type GapReason string

const (
	GapAgentMissing        GapReason = "agent_missing"
	GapAgentStale          GapReason = "agent_stale"
	GapAgentRevoked        GapReason = "agent_revoked"
	GapAgentDecommissioned GapReason = "agent_decommissioned"
	GapCapabilityMissing   GapReason = "capability_missing"
)

// Valid reports whether r is a known reconciliation gap reason.
func (r GapReason) Valid() bool {
	switch r {
	case GapAgentMissing, GapAgentStale, GapAgentRevoked, GapAgentDecommissioned, GapCapabilityMissing:
		return true
	default:
		return false
	}
}

// NormalizeCapabilities returns the canonical representation used for persistence and comparison:
// trimmed, de-duplicated, sorted, and bounded. Empty entries are ignored so JSON arrays produced by
// forms can safely contain an unset slot; non-empty values containing control characters are refused.
func NormalizeCapabilities(in []string) ([]string, error) {
	if len(in) > MaxCapabilities {
		return nil, fmt.Errorf("%w: desired state names %d capabilities, over the %d bound", shared.ErrValidation, len(in), MaxCapabilities)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		capability := strings.TrimSpace(raw)
		if capability == "" {
			continue
		}
		if len(capability) > MaxCapabilityLen {
			return nil, fmt.Errorf("%w: capability %q is longer than %d bytes", shared.ErrValidation, capability, MaxCapabilityLen)
		}
		if strings.IndexFunc(capability, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%w: capability %q contains a control character", shared.ErrValidation, capability)
		}
		if _, exists := seen[capability]; exists {
			continue
		}
		seen[capability] = struct{}{}
		out = append(out, capability)
	}
	sort.Strings(out)
	return out, nil
}

// Validate reports whether state is safe and canonical to persist. Repositories call this too, so a
// future writer cannot bypass the use case and put a non-deterministic desired document in storage.
func (s State) Validate() error {
	if s.TenantID.IsZero() {
		return fmt.Errorf("%w: desired state needs a tenant", shared.ErrValidation)
	}
	if s.AgentID.IsZero() {
		return fmt.Errorf("%w: desired state needs an agent", shared.ErrValidation)
	}
	if s.UpdatedBy.IsZero() {
		return fmt.Errorf("%w: desired state change needs an actor", shared.ErrValidation)
	}
	if s.Audit.CreatedAt.IsZero() || s.Audit.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: desired state needs audit timestamps", shared.ErrValidation)
	}
	if s.Audit.UpdatedAt.Before(s.Audit.CreatedAt) {
		return fmt.Errorf("%w: desired state updated_at precedes created_at", shared.ErrValidation)
	}
	canonical, err := NormalizeCapabilities(s.Capabilities)
	if err != nil {
		return err
	}
	if len(canonical) != len(s.Capabilities) {
		return fmt.Errorf("%w: desired capabilities must be canonical (trimmed, unique, sorted)", shared.ErrValidation)
	}
	for i := range canonical {
		if canonical[i] != s.Capabilities[i] {
			return fmt.Errorf("%w: desired capabilities must be canonical (trimmed, unique, sorted)", shared.ErrValidation)
		}
	}
	return nil
}
