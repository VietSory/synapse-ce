// Package fleetdesired reconciles operator-owned desired capabilities against the latest observed
// fleet-agent state. It is intentionally read-only during reconciliation: repeatedly viewing fleet
// health must not create database churn, and the same snapshot must always yield the same rows.
package fleetdesired

import (
	"context"
	"errors"
	"fmt"
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

// SetDesiredCapabilities replaces one agent's operator-owned desired capability set. It first proves
// the canonical AgentID exists in the same tenant; an operator cannot create an expectation bound to
// another tenant's identity. An empty set is valid and means this agent is intentionally expected to
// run no governed capability classes.
func (s *Service) SetDesiredCapabilities(ctx context.Context, in SetInput) (*desireddom.State, error) {
	if in.TenantID.IsZero() || in.AgentID.IsZero() || in.Actor.IsZero() {
		return nil, fmt.Errorf("%w: desired-state change needs tenant, agent and actor", shared.ErrValidation)
	}
	if _, err := s.agents.GetAgent(ctx, in.TenantID, in.AgentID); err != nil {
		return nil, fmt.Errorf("load desired-state agent: %w", err)
	}
	caps, err := desireddom.NormalizeCapabilities(in.Capabilities)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	createdAt := now
	if current, getErr := s.store.Get(ctx, in.TenantID, in.AgentID); getErr == nil {
		createdAt = current.Audit.CreatedAt
	} else if !errors.Is(getErr, shared.ErrNotFound) {
		return nil, fmt.Errorf("read current desired state: %w", getErr)
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
	// The desired document is already durable at this point, so an audit-backend failure must not
	// roll it back and create a split-brain between policy and the fleet. Audit implementations surface
	// their own write failures; this mirrors the existing rollout lifecycle semantics.
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: in.Actor.String(), Action: "fleet.desired_capabilities.set",
		Target: in.TenantID.String() + "/" + in.AgentID.String(),
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

// Reconcile returns one row for every desired capability, deterministically sorted by agent then
// capability. It performs two tenant-scoped reads and O(agents + desired capabilities) in-memory work;
// it does no persistence, so polling the fleet view cannot amplify writes.
func (s *Service) Reconcile(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state reconciliation needs a tenant", shared.ErrValidation)
	}
	states, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list desired states: %w", err)
	}
	agents, err := s.agents.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list fleet agents: %w", err)
	}
	now := s.clock.Now()
	type observed struct {
		agent *fleetagent.Agent
		caps  map[string]struct{}
	}
	byID := make(map[shared.ID]observed, len(agents))
	for _, agent := range agents {
		caps := make(map[string]struct{}, len(agent.Capabilities))
		for _, capability := range agent.Capabilities {
			caps[capability] = struct{}{}
		}
		byID[agent.ID] = observed{agent: agent, caps: caps}
	}

	rowCount := 0
	for _, desired := range states {
		rowCount += len(desired.Capabilities)
	}
	rows := make([]ReconciliationRow, 0, rowCount)
	for _, desired := range states {
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
			row.Health = fleetcoverage.AgentStateFrom(obs.agent.LastSeenAt, now, s.staleAfter, obs.agent.Revoked(), obs.agent.Decommissioned())
			switch row.Health {
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
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].AgentID != rows[j].AgentID {
			return rows[i].AgentID < rows[j].AgentID
		}
		return rows[i].Capability < rows[j].Capability
	})
	return rows, nil
}

// Gaps returns only uncovered desired rows. It is derived from Reconcile rather than independently
// queried so the full view and the gap-only view can never disagree for the same snapshot.
func (s *Service) Gaps(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	rows, err := s.Reconcile(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	gaps := make([]ReconciliationRow, 0, len(rows))
	for _, row := range rows {
		if !row.Covered {
			gaps = append(gaps, row)
		}
	}
	return gaps, nil
}
