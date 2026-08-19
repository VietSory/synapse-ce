// Package fleetdesired reconciles operator-owned desired capabilities for canonical host/cluster
// assets against the latest server-authoritative agent binding and observed fleet-agent state.
// Reconciliation is read-only: polling fleet health must not create database churn.
package fleetdesired

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssetReader is the narrow canonical-asset lookup needed to admit a desired-state mutation. The
// technical asset remains the durable policy subject across agent reinstall/re-enrolment.
type AssetReader interface {
	GetAssetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// CurrentBinding is the read projection #633 consumes from the server-authoritative AssetBinding
// lifecycle owned by A0.1/A3/A4. This package deliberately does not own binding creation or trust.
type CurrentBinding struct {
	TenantID shared.ID
	AssetID  shared.ID
	AgentID  shared.ID
}

// BindingReader returns the current one-agent-to-one-asset binding projection for a tenant. Historical
// bindings must not be returned here; two current agents for one asset are ambiguous and fail closed.
type BindingReader interface {
	ListCurrentBindings(ctx context.Context, tenantID shared.ID) ([]CurrentBinding, error)
}

// AgentReader is the narrow observed identity/liveness view reconciliation needs.
type AgentReader interface {
	ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
}

// Service owns desired-state mutation and reconciliation.
type Service struct {
	store      ports.FleetDesiredStore
	assets     AssetReader
	bindings   BindingReader
	agents     AgentReader
	audit      ports.AuditLogger
	clock      ports.Clock
	staleAfter time.Duration
}

// NewService validates and constructs the desired-state service. A non-positive staleAfter follows
// fleetcoverage.AgentStateFrom semantics and disables time-based staleness checks.
func NewService(store ports.FleetDesiredStore, assets AssetReader, bindings BindingReader, agents AgentReader, audit ports.AuditLogger, clock ports.Clock, staleAfter time.Duration) (*Service, error) {
	if store == nil || assets == nil || bindings == nil || agents == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: fleet desired-state service needs store, asset reader, binding reader, agent reader, audit log and clock", shared.ErrValidation)
	}
	return &Service{store: store, assets: assets, bindings: bindings, agents: agents, audit: audit, clock: clock, staleAfter: staleAfter}, nil
}

// SetInput replaces one canonical asset's non-empty desired capability set.
type SetInput struct {
	TenantID     shared.ID
	AssetID      shared.ID
	Capabilities []string
	Actor        shared.ID
}

// ClearInput identifies one desired policy to remove. Clear is explicit so absence and an intentionally
// empty array can never become two representations of the same state.
type ClearInput struct {
	TenantID shared.ID
	AssetID  shared.ID
	Actor    shared.ID
}

// SetDesiredCapabilities replaces one host/cluster asset's operator-owned desired capability set.
// The canonical asset, not the current AgentID, owns the policy. Therefore a replacement agent bound
// to the same asset can satisfy existing intent without a policy rewrite. Store CAS prevents concurrent
// writers that both read the same version from silently overwriting one another.
func (s *Service) SetDesiredCapabilities(ctx context.Context, in SetInput) (*desireddom.State, error) {
	if in.TenantID.IsZero() || in.AssetID.IsZero() || in.Actor.IsZero() {
		return nil, fmt.Errorf("%w: desired-state change needs tenant, canonical asset and actor", shared.ErrValidation)
	}
	caps, err := desireddom.NormalizeCapabilities(in.Capabilities)
	if err != nil {
		return nil, err
	}
	if len(caps) == 0 {
		return nil, fmt.Errorf("%w: desired capability set is empty; use ClearDesiredCapabilities", shared.ErrValidation)
	}

	var current *desireddom.State
	if got, getErr := s.store.Get(ctx, in.TenantID, in.AssetID); getErr == nil {
		if err := validateStoredState(got, in.TenantID, in.AssetID); err != nil {
			return nil, err
		}
		current = got
		// Declarative re-apply is a true no-op: no asset read, clock read, write, or audit churn.
		if slices.Equal(current.Capabilities, caps) {
			return current, nil
		}
	} else if !errors.Is(getErr, shared.ErrNotFound) {
		return nil, fmt.Errorf("read current desired state: %w", getErr)
	}

	version := int64(1)
	if current != nil {
		if current.Version == 1<<63-1 {
			return nil, fmt.Errorf("%w: desired state version exhausted for asset %s", shared.ErrConflict, in.AssetID)
		}
		version = current.Version + 1
	}

	// Validate the durable policy subject on every semantic change. This keeps a stale/corrupt desired
	// row from being mutated after its canonical host/cluster identity no longer exists, while Clear
	// remains available as the recovery path.
	subject, err := s.assets.GetAssetByID(ctx, in.TenantID, in.AssetID)
	if err != nil {
		return nil, fmt.Errorf("load desired-state asset: %w", err)
	}
	if subject == nil {
		return nil, fmt.Errorf("%w: asset reader returned nil for asset %s", shared.ErrValidation, in.AssetID)
	}
	if subject.TenantID != in.TenantID || subject.ID != in.AssetID {
		return nil, fmt.Errorf("%w: asset reader returned identity %s/%s, want %s/%s",
			shared.ErrValidation, subject.TenantID, subject.ID, in.TenantID, in.AssetID)
	}
	if !desireddom.SupportedAssetKind(subject.Kind) {
		return nil, fmt.Errorf("%w: desired state may target only host/cluster assets, got %s kind %q",
			shared.ErrValidation, subject.ID, subject.Kind)
	}

	now := s.clock.Now().UTC()
	createdAt := now
	if current != nil {
		createdAt = current.Audit.CreatedAt
	}
	state := &desireddom.State{
		TenantID: in.TenantID, AssetID: in.AssetID, Capabilities: caps, UpdatedBy: in.Actor, Version: version,
		Audit: shared.Audit{CreatedAt: createdAt, UpdatedAt: now},
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if err := s.store.Put(ctx, state); err != nil {
		return nil, fmt.Errorf("store desired state: %w", err)
	}
	s.record(ctx, state, in.Actor, "fleet.desired_capabilities.set", map[string]string{
		"capabilities": strings.Join(caps, ","),
	}, now)
	return state, nil
}

// ClearDesiredCapabilities removes one desired policy. Clearing an already-absent policy is a
// side-effect-free success. If a concurrent writer replaces the version after this method reads it,
// the CAS delete returns ErrConflict and preserves the newer policy.
func (s *Service) ClearDesiredCapabilities(ctx context.Context, in ClearInput) error {
	if in.TenantID.IsZero() || in.AssetID.IsZero() || in.Actor.IsZero() {
		return fmt.Errorf("%w: desired-state clear needs tenant, canonical asset and actor", shared.ErrValidation)
	}
	current, err := s.store.Get(ctx, in.TenantID, in.AssetID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read desired state before clear: %w", err)
	}
	if err := validateStoredState(current, in.TenantID, in.AssetID); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, in.TenantID, in.AssetID, current.Version); err != nil {
		return fmt.Errorf("clear desired state: %w", err)
	}
	now := s.clock.Now().UTC()
	s.record(ctx, current, in.Actor, "fleet.desired_capabilities.clear", map[string]string{
		"previous_capabilities": strings.Join(current.Capabilities, ","),
	}, now)
	return nil
}

// Get returns one canonical asset's desired state and fails closed if storage returns malformed or
// cross-identity data.
func (s *Service) Get(ctx context.Context, tenantID, assetID shared.ID) (*desireddom.State, error) {
	if tenantID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and asset", shared.ErrValidation)
	}
	state, err := s.store.Get(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if err := validateStoredState(state, tenantID, assetID); err != nil {
		return nil, err
	}
	return state, nil
}

// ReconciliationRow is one desired asset capability compared with the current bound agent.
type ReconciliationRow struct {
	AssetID    string                    `json:"asset_id"`
	AgentID    string                    `json:"agent_id,omitempty"`
	Capability string                    `json:"capability"`
	Health     fleetcoverage.AgentHealth `json:"agent_health,omitempty"`
	Covered    bool                      `json:"covered"`
	GapReason  desireddom.GapReason      `json:"gap_reason,omitempty"`
	Detail     string                    `json:"detail,omitempty"`
	LastSeen   time.Time                 `json:"last_seen,omitempty"`
}

type observedAgent struct {
	agent  *fleetagent.Agent
	health fleetcoverage.AgentHealth
	caps   map[string]struct{}
}

// Reconcile returns one row for every desired capability, deterministically sorted by asset then
// capability. It performs bounded tenant-scoped reads and no persistence, so polling cannot amplify
// writes. Observed capability maps retain only capabilities this policy actually asks about.
func (s *Service) Reconcile(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	return s.reconcile(ctx, tenantID, false)
}

// Gaps returns only uncovered desired rows from the same reconciliation path as Reconcile.
func (s *Service) Gaps(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	return s.reconcile(ctx, tenantID, true)
}

func (s *Service) reconcile(ctx context.Context, tenantID shared.ID, gapsOnly bool) ([]ReconciliationRow, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state reconciliation needs a tenant", shared.ErrValidation)
	}
	states, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list desired states: %w", err)
	}
	if len(states) == 0 {
		return []ReconciliationRow{}, nil
	}

	ordered := append([]*desireddom.State(nil), states...)
	desiredIDs := make(map[shared.ID]struct{}, len(ordered))
	rowCount := 0
	for i, desired := range ordered {
		if desired == nil {
			return nil, fmt.Errorf("%w: desired-state snapshot contains nil row at index %d", shared.ErrValidation, i)
		}
		if err := desired.Validate(); err != nil {
			return nil, fmt.Errorf("invalid desired-state snapshot for asset %s: %w", desired.AssetID, err)
		}
		if desired.TenantID != tenantID {
			return nil, fmt.Errorf("%w: desired-state snapshot for asset %s belongs to tenant %s, want %s",
				shared.ErrValidation, desired.AssetID, desired.TenantID, tenantID)
		}
		if _, duplicate := desiredIDs[desired.AssetID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate desired-state row for asset %s", shared.ErrValidation, desired.AssetID)
		}
		desiredIDs[desired.AssetID] = struct{}{}
		rowCount += len(desired.Capabilities)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].AssetID < ordered[j].AssetID })

	bindings, err := s.bindings.ListCurrentBindings(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list current agent bindings: %w", err)
	}
	bindingByAsset := make(map[shared.ID]CurrentBinding, min(len(bindings), len(ordered)))
	seenBindingAssets := make(map[shared.ID]struct{}, len(bindings))
	assetByAgent := make(map[shared.ID]shared.ID, len(bindings))
	for i, binding := range bindings {
		if binding.TenantID.IsZero() || binding.AssetID.IsZero() || binding.AgentID.IsZero() {
			return nil, fmt.Errorf("%w: binding snapshot contains empty identity at index %d", shared.ErrValidation, i)
		}
		if binding.TenantID != tenantID {
			return nil, fmt.Errorf("%w: binding %s/%s belongs to tenant %s, want %s",
				shared.ErrValidation, binding.AssetID, binding.AgentID, binding.TenantID, tenantID)
		}
		if _, duplicate := seenBindingAssets[binding.AssetID]; duplicate {
			return nil, fmt.Errorf("%w: multiple current agent bindings for asset %s", shared.ErrValidation, binding.AssetID)
		}
		seenBindingAssets[binding.AssetID] = struct{}{}
		if other, duplicate := assetByAgent[binding.AgentID]; duplicate {
			return nil, fmt.Errorf("%w: current agent %s is bound to both assets %s and %s",
				shared.ErrValidation, binding.AgentID, other, binding.AssetID)
		}
		assetByAgent[binding.AgentID] = binding.AssetID
		if _, wanted := desiredIDs[binding.AssetID]; wanted {
			bindingByAsset[binding.AssetID] = binding
		}
	}

	wantedByAgent := make(map[shared.ID]map[string]struct{}, len(bindingByAsset))
	for _, desired := range ordered {
		binding, ok := bindingByAsset[desired.AssetID]
		if !ok {
			continue
		}
		wanted := make(map[string]struct{}, len(desired.Capabilities))
		for _, capability := range desired.Capabilities {
			wanted[capability] = struct{}{}
		}
		wantedByAgent[binding.AgentID] = wanted
	}

	byID := make(map[shared.ID]observedAgent, len(wantedByAgent))
	if len(wantedByAgent) > 0 {
		agents, err := s.agents.ListAgents(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("list fleet agents: %w", err)
		}
		now := s.clock.Now().UTC()
		seenAgents := make(map[shared.ID]struct{}, len(agents))
		for i, agent := range agents {
			if agent == nil {
				return nil, fmt.Errorf("%w: observed-agent snapshot contains nil row at index %d", shared.ErrValidation, i)
			}
			if agent.ID.IsZero() {
				return nil, fmt.Errorf("%w: observed-agent snapshot contains an empty agent id at index %d", shared.ErrValidation, i)
			}
			if agent.TenantID != tenantID {
				return nil, fmt.Errorf("%w: observed agent %s belongs to tenant %s, want %s",
					shared.ErrValidation, agent.ID, agent.TenantID, tenantID)
			}
			if _, duplicate := seenAgents[agent.ID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate observed-agent row for agent %s", shared.ErrValidation, agent.ID)
			}
			seenAgents[agent.ID] = struct{}{}
			wanted, relevant := wantedByAgent[agent.ID]
			if !relevant {
				continue
			}
			caps := make(map[string]struct{}, len(wanted))
			for _, raw := range agent.Capabilities {
				capability := strings.TrimSpace(raw)
				if _, keep := wanted[capability]; keep {
					caps[capability] = struct{}{}
				}
			}
			byID[agent.ID] = observedAgent{
				agent:  agent,
				health: fleetcoverage.AgentStateFrom(agent.LastSeenAt, now, s.staleAfter, agent.Revoked(), agent.Decommissioned()),
				caps:   caps,
			}
		}
	}

	outCap := rowCount
	if gapsOnly {
		outCap = 0
	}
	rows := make([]ReconciliationRow, 0, outCap)
	for _, desired := range ordered {
		binding, bound := bindingByAsset[desired.AssetID]
		for _, capability := range desired.Capabilities {
			row := ReconciliationRow{AssetID: desired.AssetID.String(), Capability: capability}
			if !bound {
				row.GapReason = desireddom.GapAgentMissing
				row.Detail = "no current agent is bound to this desired asset"
				rows = append(rows, row)
				continue
			}
			row.AgentID = binding.AgentID.String()
			obs, exists := byID[binding.AgentID]
			if !exists {
				row.GapReason = desireddom.GapAgentMissing
				row.Detail = "the asset's current binding names an agent with no observed registry row"
				rows = append(rows, row)
				continue
			}
			row.LastSeen = obs.agent.LastSeenAt
			row.Health = obs.health
			switch obs.health {
			case fleetcoverage.AgentRevoked:
				row.GapReason = desireddom.GapAgentRevoked
				row.Detail = "the bound agent was revoked and cannot provide coverage"
			case fleetcoverage.AgentDecommissioned:
				row.GapReason = desireddom.GapAgentDecommissioned
				row.Detail = "the bound agent was decommissioned and no replacement currently satisfies this asset intent"
			case fleetcoverage.AgentStale:
				row.GapReason = desireddom.GapAgentStale
				row.Detail = "the bound agent heartbeat is stale"
			case fleetcoverage.AgentHealthy:
				if _, advertised := obs.caps[capability]; advertised {
					row.Covered = true
				} else {
					row.GapReason = desireddom.GapCapabilityMissing
					row.Detail = "the healthy bound agent does not advertise the desired capability"
				}
			default:
				return nil, fmt.Errorf("%w: derived invalid agent health %q for agent %s", shared.ErrValidation, obs.health, binding.AgentID)
			}
			if gapsOnly && row.Covered {
				continue
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func validateStoredState(state *desireddom.State, tenantID, assetID shared.ID) error {
	if state == nil {
		return fmt.Errorf("%w: desired-state store returned a nil row", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("invalid current desired state: %w", err)
	}
	if state.TenantID != tenantID || state.AssetID != assetID {
		return fmt.Errorf("%w: desired-state store returned identity %s/%s, want %s/%s",
			shared.ErrValidation, state.TenantID, state.AssetID, tenantID, assetID)
	}
	return nil
}

// record audits a successful desired-state mutation. As with fleet rollout, a write may already be
// externally observable by the time the separate audit sink fails; rolling policy back would create a
// worse split-brain. Audit delivery is therefore best-effort here and failures are surfaced by the audit
// implementation's own alerting. The explicit helper makes that non-atomic contract intentional rather
// than an accidental ignored error.
func (s *Service) record(ctx context.Context, state *desireddom.State, actor shared.ID, action string, extra map[string]string, at time.Time) {
	metadata := map[string]string{
		"tenant_id":      state.TenantID.String(),
		"asset_id":       state.AssetID.String(),
		"policy_version": fmt.Sprintf("%d", state.Version),
	}
	for k, v := range extra {
		if v != "" {
			metadata[k] = v
		}
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: action, Target: state.AssetID.String(), Metadata: metadata, At: at,
	})
}
