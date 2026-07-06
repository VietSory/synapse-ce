package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestStateTransitions(t *testing.T) {
	// A representative set of the legal control-flow edges.
	legal := [][2]State{
		{StatePlan, StateValidate}, {StatePlan, StateDone},
		{StateValidate, StateApprove}, {StateValidate, StateReflect}, // rejected-in-Go loops back
		{StateApprove, StateExecute}, {StateApprove, StateReflect}, // denied loops back
		{StateExecute, StateObserve}, {StateObserve, StateRecord},
		{StateRecord, StateReflect}, {StateReflect, StatePlan}, {StateReflect, StateDone},
	}
	for _, e := range legal {
		if !CanTransition(e[0], e[1]) {
			t.Errorf("transition %s→%s should be legal", e[0], e[1])
		}
	}
	// Off-graph transitions an observation/model-response must NOT be able to force.
	illegal := [][2]State{
		{StatePlan, StateExecute},     // cannot skip validate+approve
		{StateValidate, StateExecute}, // cannot skip approve
		{StateObserve, StateExecute},  // cannot re-execute without a new proposal
		{StateDone, StatePlan},        // terminal
	}
	for _, e := range illegal {
		if CanTransition(e[0], e[1]) {
			t.Errorf("transition %s→%s must be ILLEGAL (control flow is Go, not model-steered)", e[0], e[1])
		}
	}
}

func TestStateTerminal(t *testing.T) {
	if !StateDone.Terminal() || !StateFailed.Terminal() {
		t.Error("done/failed must be terminal")
	}
	if StatePlan.Terminal() || StateExecute.Terminal() {
		t.Error("plan/execute are not terminal")
	}
}

func TestStatusTerminal(t *testing.T) {
	for _, s := range []Status{StatusSucceeded, StatusFailed, StatusCancelled} {
		if !s.Terminal() {
			t.Errorf("%s must be terminal", s)
		}
	}
	for _, s := range []Status{StatusRunning, StatusAwaitingApproval} {
		if s.Terminal() {
			t.Errorf("%s must NOT be terminal (resumable)", s)
		}
	}
}

func TestNewSessionValidates(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	if _, err := NewSession("", "e1", "alice", "find subdomains", "m", "b", "h", now, 1000); !errors.Is(err, shared.ErrValidation) {
		t.Error("empty id must fail validation")
	}
	if _, err := NewSession("s1", "e1", "", "goal", "m", "b", "h", now, 1000); !errors.Is(err, shared.ErrValidation) {
		t.Error("missing human initiator must fail (attribution required)")
	}
	if _, err := NewSession("s1", "e1", "alice", "", "m", "b", "h", now, 1000); !errors.Is(err, shared.ErrValidation) {
		t.Error("empty goal must fail validation")
	}
	s, err := NewSession("s1", "e1", "alice", "find subdomains", "gpt-x", "http://localhost:20128/v1", "abc", now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != StatusRunning {
		t.Errorf("new session should be running, got %s", s.Status)
	}
	if s.AgentActor() != "agent:s1" {
		t.Errorf("agent actor = %q, want agent:s1 (distinct from the human initiator)", s.AgentActor())
	}
}

func TestApprovalAdmitted(t *testing.T) {
	if !ApprovalApproved.Admitted() {
		t.Error("approved must admit")
	}
	for _, s := range []ApprovalState{ApprovalPending, ApprovalDenied, ApprovalTimeout} {
		if s.Admitted() {
			t.Errorf("%s must NOT admit execution (fail-closed)", s)
		}
	}
}

func TestBudgetExhausted(t *testing.T) {
	s := Session{TokenBudgetMax: 1000, TokensUsed: 999}
	if s.BudgetExhausted() {
		t.Error("under budget must not be exhausted")
	}
	s.TokensUsed = 1000
	if !s.BudgetExhausted() {
		t.Error("at budget must be exhausted")
	}
	if (Session{TokenBudgetMax: 0, TokensUsed: 1e9}).BudgetExhausted() {
		t.Error("budget 0 = unbounded")
	}
}

func TestApprovalModeAutoApproves(t *testing.T) {
	// Intrusive is ALWAYS manual, regardless of mode.
	for _, m := range []ApprovalMode{ModeManual, ModeFilter, ModeAuto} {
		if m.AutoApproves(RiskIntrusive) {
			t.Errorf("mode %s must NOT auto-approve Intrusive", m)
		}
	}
	// Manual = nothing auto.
	for _, r := range []RiskClass{RiskRead, RiskActive, RiskIntrusive} {
		if ModeManual.AutoApproves(r) {
			t.Errorf("ModeManual must not auto-approve %s", r)
		}
	}
	// Filter = only Read auto.
	if !ModeFilter.AutoApproves(RiskRead) || ModeFilter.AutoApproves(RiskActive) {
		t.Error("ModeFilter: Read auto, Active manual")
	}
	// Auto = Read + Active auto.
	if !ModeAuto.AutoApproves(RiskRead) || !ModeAuto.AutoApproves(RiskActive) {
		t.Error("ModeAuto: Read + Active auto")
	}
	// Unknown mode fails safe to manual.
	if ApprovalMode("bogus").AutoApproves(RiskRead) {
		t.Error("unknown mode must fail safe (no auto-approve)")
	}
}
