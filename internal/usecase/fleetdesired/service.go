// Package fleetdesired reconciles operator-owned desired capabilities against the latest observed
// fleet-agent state. It is intentionally read-only during reconciliation: repeatedly viewing fleet
// health must not create database churn, and the same snapshot must always yield the same rows.
package fleetdesired

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentReader is the narrow identity/liveness view reconciliation needs.
type AgentReader interface {
	GetAgent(ctx context.Context, tenantID, agentID shared.ID) (*fleetagent.Agent, error)
	ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
}

// Service owns desired-state mutation and reconciliation.
type Service struct {
	store      ports.FleetDesiredStore
	agents     AgentReader
	audit      ports.AuditLogger
	clock      ports.Clock
	staleAfter time.Duration
}

// NewService validates and constructs the desired-state service. A non-positive staleAfter follows
// fleetcoverage.AgentStateFrom semantics and disables time-based staleness checks.
func NewService(store ports.FleetDesiredStore, agents AgentReader, audit ports.AuditLogger, clock ports.Clock, staleAfter time.Duration) (*Service, error) {
	if store == nil || agents == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: fleet desired-state service needs a store, agent reader, audit log and clock", shared.ErrValidation)
	}
	return &Service{store: store, agents: agents, audit: audit, clock: clock, staleAfter: staleAfter}, nil
}

// SetInput atomically replaces one agent's desired capability set.
type SetInput struct {
	TenantID     shared.ID
	AgentID      shared.ID
	Capabilities []string
	Actor        shared.ID
}

// SetDesiredCapabilities replaces one agent's operator-owned desired capability set. Creating a NEW
// intent first proves the canonical AgentID exists in the same tenant; after that, the intent is
// independent of the observed row and can still be changed or cleared if the agent disappears. That
// matches reconciliation: observed deletion is a gap, not ownership of (or a delete cascade for) policy.
// An empty set is valid and means this agent is intentionally expected to run no governed capability classes.
func (s *Service) SetDesiredCapabilities(ctx context.Context, in SetInput) (*desireddom.State, error) {
	if in.TenantID.IsZero() || in.AgentID.IsZero() || in.Actor.IsZero() {
		return nil, fmt.Errorf("%w: desired-state change needs tenant, agent and actor", shared.ErrValidation)
	}
	caps, err := desireddom.NormalizeCapabilities(in.Capabilities)
	if err != nil {
		return nil, err
	}
	var createdAt time.Time
	if current, getErr := s.store.Get(ctx, in.TenantID, in.AgentID); getErr == nil {
		if current == nil {
			return nil, fmt.Errorf("%w: desired-state store returned a nil current row", shared.ErrValidation)
		}
		if err := current.Validate(); err != nil {
			return nil, fmt.Errorf("invalid current desired state: %w", err)
		}
		if current.TenantID != in.TenantID || current.AgentID != in.AgentID {
			return nil, fmt.Errorf("%w: desired-state store returned identity %s/%s, want %s/%s",
				shared.ErrValidation, current.TenantID, current.AgentID, in.TenantID, in.AgentID)
		}
		// Declarative re-apply is a no-op. A desired-state controller may submit the same canonical
		// intent repeatedly; rewriting it would create database and audit churn without changing state.
		if slices.Equal(current.Capabilities, caps) {
			return current, nil
		}
		createdAt = current.Audit.CreatedAt
	} else if errors.Is(getErr, shared.ErrNotFound) {
		// Only creation depends on the observed registry. Once desired intent exists, requiring the
		// observed row here would make an agent purge freeze stale policy forever — including preventing
		// the operator from clearing it with an empty set.
		if _, err := s.agents.GetAgent(ctx, in.TenantID, in.AgentID); err != nil {
			return nil, fmt.Errorf("load desired-state agent: %w", err)
		}
	} else {
		return nil, fmt.Errorf("read current desired state: %w", getErr)
	}
	now := s.clock.Now().UTC()
	if createdAt.IsZero() {
		createdAt = now
	}
	state := &desireddom.State{
		TenantID: in.TenantID, AgentID: in.AgentID, Capabilities: caps, UpdatedBy: in.Actor,
		Audit: shared.Audit{CreatedAt: createdAt, UpdatedAt: now},
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if err := s.store.Put(ctx, state); err != nil {
		return nil, fmt.Errorf("store desired state: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: in.Actor.String(), Action: "fleet.desired_capabilities.set",
		Target:   in.TenantID.String() + "/" + in.AgentID.String(),
		Metadata: map[string]string{"capabilities": strings.Join(caps, ",")}, At: now,
	})
	return state, nil
}

// Get returns one agent's desired state.
func (s *Service) Get(ctx context.Context, tenantID, agentID shared.ID) (*desireddom.State, error) {
	if tenantID.IsZero() || agentID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and agent", shared.ErrValidation)
	}
	return s.store.Get(ctx, tenantID, agentID)
}

// ReconciliationRow is one desired capability compared with the latest observed agent state.
type ReconciliationRow struct {
	AgentID    string                    `json:"agent_id"`
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

// Reconcile returns one row for every desired capability, deterministically sorted by agent then
// capability. It performs two tenant-scoped reads and O(A + C + D log D + R) in-memory work, where D
// is desired agents and R is returned rows. It does no persistence, so polling cannot amplify writes.
func (s *Service) Reconcile(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	return s.reconcile(ctx, tenantID, false)
}

// Gaps returns only uncovered desired rows from the same reconciliation path as Reconcile. Passing the
// projection filter into the shared path avoids allocating the full covered fleet just to discard it.
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

	ordered := append([]*desireddom.State(nil), states...)
	desiredIDs := make(map[shared.ID]struct{}, len(ordered))
	rowCount := 0
	for i, desired := range ordered {
		if desired == nil {
			return nil, fmt.Errorf("%w: desired-state snapshot contains nil row at index %d", shared.ErrValidation, i)
		}
		if err := desired.Validate(); err != nil {
			return nil, fmt.Errorf("invalid desired-state snapshot for agent %s: %w", desired.AgentID, err)
		}
		if desired.TenantID != tenantID {
			return nil, fmt.Errorf("%w: desired-state snapshot for agent %s belongs to tenant %s, want %s", shared.ErrValidation, desired.AgentID, desired.TenantID, tenantID)
		}
		if _, duplicate := desiredIDs[desired.AgentID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate desired-state row for agent %s", shared.ErrValidation, desired.AgentID)
		}
		desiredIDs[desired.AgentID] = struct{}{}
		rowCount += len(desired.Capabilities)
	}
	// Sort only the desired documents, not every expanded capability row. Each State already validates
	// that its capabilities are sorted, so this keeps deterministic output at D log D rather than R log R.
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].AgentID < ordered[j].AgentID })

	agents, err := s.agents.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list fleet agents: %w", err)
	}
	now := s.clock.Now()
	seenAgents := make(map[shared.ID]struct{}, len(agents))
	observedCap := len(agents)
	if len(ordered) < observedCap {
		observedCap = len(ordered)
	}
	byID := make(map[shared.ID]observedAgent, observedCap)
	for i, agent := range agents {
		if agent == nil {
			return nil, fmt.Errorf("%w: observed-agent snapshot contains nil row at index %d", shared.ErrValidation, i)
		}
		if agent.ID.IsZero() {
			return nil, fmt.Errorf("%w: observed-agent snapshot contains an empty agent id at index %d", shared.ErrValidation, i)
		}
		if agent.TenantID != tenantID {
			return nil, fmt.Errorf("%w: observed agent %s belongs to tenant %s, want %s", shared.ErrValidation, agent.ID, agent.TenantID, tenantID)
		}
		if _, duplicate := seenAgents[agent.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate observed-agent row for agent %s", shared.ErrValidation, agent.ID)
		}
		seenAgents[agent.ID] = struct{}{}
		if _, wanted := desiredIDs[agent.ID]; !wanted {
			continue
		}
		caps := make(map[string]struct{}, len(agent.Capabilities))
		for _, capability := range agent.Capabilities {
			capability = strings.TrimSpace(capability)
			if capability != "" {
				caps[capability] = struct{}{}
			}
		}
		byID[agent.ID] = observedAgent{
			agent:  agent,
			health: fleetcoverage.AgentStateFrom(agent.LastSeenAt, now, s.staleAfter, agent.Revoked(), agent.Decommissioned()),
			caps:   caps,
		}
	}

	outCap := rowCount
	if gapsOnly {
		outCap = 0 // a healthy fleet should not allocate memory proportional to all covered rows
	}
	rows := make([]ReconciliationRow, 0, outCap)
	for _, desired := range ordered {
		obs, exists := byID[desired.AgentID]
		for _, capability := range desired.Capabilities {
			row := ReconciliationRow{AgentID: desired.AgentID.String(), Capability: capability}
			if !exists {
				row.GapReason = desireddom.GapAgentMissing
				row.Detail = "no current observed agent record exists for this desired identity"
				rows = append(rows, row)
				continue
			}
			row.LastSeen = obs.agent.LastSeenAt
			row.Health = obs.health
			switch obs.health {
			case fleetcoverage.AgentRevoked:
				row.GapReason = desireddom.GapAgentRevoked
				row.Detail = "the desired agent was revoked and cannot provide coverage"
			case fleetcoverage.AgentDecommissioned:
				row.GapReason = desireddom.GapAgentDecommissioned
				row.Detail = "the desired agent was decommissioned and no replacement satisfies this intent"
			case fleetcoverage.AgentStale:
				row.GapReason = desireddom.GapAgentStale
				row.Detail = "the desired agent heartbeat is stale"
			case fleetcoverage.AgentHealthy:
				if _, advertised := obs.caps[capability]; advertised {
					row.Covered = true
				} else {
					row.GapReason = desireddom.GapCapabilityMissing
					row.Detail = "the healthy agent does not advertise the desired capability"
				}
			}
			if gapsOnly && row.Covered {
				continue
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}
