// Package dastworkflow coordinates the governed DAST verification lifecycle.
//
// It deliberately reuses Synapse's existing approval and safety gate primitives instead of
// inventing a second approval path: propose creates an intrusive, approval-required action; decide
// records a human decision; run re-admits the decided action through safety.Gate and then calls the
// safe dastrunner.
package dastworkflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type Service struct {
	gate      *safety.Gate
	approvals *approval.Service
	store     ports.ApprovalStore
	runner    *dastrunner.Service
	clock     ports.Clock
	ids       ports.IDGenerator
}

func NewService(gate *safety.Gate, approvals *approval.Service, store ports.ApprovalStore, runner *dastrunner.Service, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if gate == nil || approvals == nil || store == nil || runner == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: dast workflow requires gate, approvals, store, runner, clock, and ids", shared.ErrValidation)
	}
	return &Service{gate: gate, approvals: approvals, store: store, runner: runner, clock: clock, ids: ids}, nil
}

type Proposal struct {
	Action   agent.ProposedAction   `json:"action"`
	Decision agent.ApprovalDecision `json:"decision"`
}

func (s *Service) Propose(ctx context.Context, actor string, engagementID shared.ID, probe dastrunner.Probe) (Proposal, error) {
	if actor == "" {
		return Proposal{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if engagementID == "" || probe.JudgmentID == "" {
		return Proposal{}, fmt.Errorf("%w: engagement id and judgment id are required", shared.ErrValidation)
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = "GET"
	}
	p := agent.ProposedAction{
		ID:           s.ids.NewID(),
		SessionID:    shared.ID("dast:" + probe.JudgmentID.String()),
		EngagementID: engagementID,
		Tool:         dastrunner.ToolRunDASTVerifier,
		Action:       dastrunner.ActionSafeHTTPProbe,
		Target:       engagement.Target{Kind: engagement.TargetURL, Value: strings.TrimSpace(probe.URL)},
		Argv:         []string{"curl", "-X", method, strings.TrimSpace(probe.URL)},
		Risk:         agent.RiskIntrusive,
		Rationale:    strings.TrimSpace(probe.Rationale),
		ProposedAt:   s.clock.Now(),
	}
	if p.Rationale == "" {
		p.Rationale = "runtime verifier proof requested for " + probe.JudgmentID.String()
	}
	_, err := s.gate.Admit(ctx, p, actor)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		return Proposal{}, err
	}
	_, dec, gerr := s.store.Get(ctx, p.ID)
	if gerr != nil {
		return Proposal{}, gerr
	}
	return Proposal{Action: p, Decision: dec}, nil
}

func (s *Service) Decide(ctx context.Context, human string, engagementID, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error) {
	p, _, err := s.store.Get(ctx, actionID)
	if err != nil {
		return agent.ApprovalDecision{}, err
	}
	if p.EngagementID != engagementID || p.Tool != dastrunner.ToolRunDASTVerifier || p.Action != dastrunner.ActionSafeHTTPProbe {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: DAST approval not found for this engagement", shared.ErrNotFound)
	}
	return s.approvals.Decide(ctx, human, actionID, approve, reason)
}

func (s *Service) Run(ctx context.Context, actor string, engagementID, actionID shared.ID, probe dastrunner.Probe) (dastrunner.Result, error) {
	p, _, err := s.store.Get(ctx, actionID)
	if err != nil {
		return dastrunner.Result{}, err
	}
	if p.EngagementID != engagementID || p.Tool != dastrunner.ToolRunDASTVerifier || p.Action != dastrunner.ActionSafeHTTPProbe {
		return dastrunner.Result{}, fmt.Errorf("%w: DAST approval not found for this engagement", shared.ErrNotFound)
	}
	if probe.URL != p.Target.Value {
		return dastrunner.Result{}, fmt.Errorf("%w: probe URL must match the approved DAST action target", shared.ErrValidation)
	}
	adm, err := s.gate.Admit(ctx, p, actor)
	if err != nil {
		return dastrunner.Result{}, err
	}
	return s.runner.Execute(ctx, adm, probe)
}
