// Package fleetdesired defines control-plane-owned fleet intent for canonical technical assets.
//
// Desired state is deliberately separate from fleetagent.Agent.Capabilities. Capabilities are an
// OBSERVATION reported by an untrusted agent; desired capabilities are an operator decision. Folding
// the two together would let an agent erase a missing sensor by ceasing to advertise it. The durable
// subject is the canonical host/cluster AssetID, not an enrolment-scoped AgentID, so replacing or
// re-enrolling an agent does not orphan the policy it is expected to satisfy.
package fleetdesired

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// MaxCapabilities bounds the canonical desired set for one host/cluster.
	MaxCapabilities = 64
	// MaxCapabilityInputs separately bounds raw mutation input. This allows benign duplicates while
	// preventing an attacker or broken client from making normalization unbounded.
	MaxCapabilityInputs = 256
	// MaxCapabilityLen bounds one capability identifier while leaving room for namespaced values.
	MaxCapabilityLen = 128
)

// State is the operator-owned desired capability set for one canonical host/cluster AssetID. Asset
// kind is deliberately not duplicated here: fleet_assets is authoritative for that immutable
// identity property, while this aggregate stores only policy-owned data.
type State struct {
	TenantID     shared.ID
	AssetID      shared.ID
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

// SupportedAssetKind reports whether desired fleet policy may target this technical asset kind. #633
// governs one VM host or one Kubernetes cluster; workload/image policy belongs to other controllers.
func SupportedAssetKind(kind asset.Kind) bool {
	return kind == asset.KindHost || kind == asset.KindCluster
}

// NormalizeCapabilities returns the canonical persistence/comparison representation: trimmed,
// de-duplicated, sorted, and bounded. Empty raw slots are ignored; an empty canonical result is handled
// by the mutation API (which requires an explicit Clear rather than persisting a meaningless empty row).
func NormalizeCapabilities(in []string) ([]string, error) {
	if len(in) > MaxCapabilityInputs {
		return nil, fmt.Errorf("%w: desired state received %d capability inputs, over the %d input bound",
			shared.ErrValidation, len(in), MaxCapabilityInputs)
	}
	seen := make(map[string]struct{}, min(len(in), MaxCapabilities))
	out := make([]string, 0, min(len(in), MaxCapabilities))
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
		if len(out) == MaxCapabilities {
			return nil, fmt.Errorf("%w: desired state names more than %d distinct capabilities", shared.ErrValidation, MaxCapabilities)
		}
		seen[capability] = struct{}{}
		out = append(out, capability)
	}
	sort.Strings(out)
	return out, nil
}

// Validate reports whether state is safe and canonical to persist. Subject existence/type is an
// admission invariant checked against the canonical asset store by the use case; this aggregate only
// validates fields it owns.
func (s State) Validate() error {
	if s.TenantID.IsZero() {
		return fmt.Errorf("%w: desired state needs a tenant", shared.ErrValidation)
	}
	if s.AssetID.IsZero() {
		return fmt.Errorf("%w: desired state needs a canonical asset", shared.ErrValidation)
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
	if len(canonical) == 0 {
		return fmt.Errorf("%w: desired state must contain at least one capability; clear the intent instead", shared.ErrValidation)
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
