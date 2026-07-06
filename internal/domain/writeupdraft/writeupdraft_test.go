package writeupdraft

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var tClock = time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

func proposeValid(t *testing.T) Draft {
	t.Helper()
	d, err := Propose("wd:1", "eng:1", "find:1", "  Stored XSS in profile.  ", "Encode on output.", "agent:writer", tClock)
	if err != nil {
		t.Fatalf("Propose valid: %v", err)
	}
	return d
}

func TestProposeValidTrimsAndSetsProposed(t *testing.T) {
	d := proposeValid(t)
	if d.State != StateProposed {
		t.Errorf("state = %q, want proposed", d.State)
	}
	if d.Description != "Stored XSS in profile." {
		t.Errorf("description not trimmed: %q", d.Description)
	}
	if d.ProposedBy != "agent:writer" || d.DecidedBy != "" {
		t.Errorf("attribution wrong: proposedBy=%q decidedBy=%q", d.ProposedBy, d.DecidedBy)
	}
}

func TestProposeFailClosed(t *testing.T) {
	long := strings.Repeat("x", maxDescriptionLen+1)
	cases := []struct {
		name                         string
		id, eng, find, desc, rem, by string
	}{
		{"no id", "", "eng:1", "find:1", "d", "r", "agent"},
		{"no engagement", "wd:1", "", "find:1", "d", "r", "agent"},
		{"no finding", "wd:1", "eng:1", "", "d", "r", "agent"},
		{"no proposer", "wd:1", "eng:1", "find:1", "d", "r", "  "},
		{"both fields empty", "wd:1", "eng:1", "find:1", "   ", "", "agent"},
		{"description too long", "wd:1", "eng:1", "find:1", long, "", "agent"},
		{"remediation too long", "wd:1", "eng:1", "find:1", "", long, "agent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Propose(shared.ID(c.id), shared.ID(c.eng), shared.ID(c.find), c.desc, c.rem, c.by, tClock); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestEditOnlyWhenProposed(t *testing.T) {
	d := proposeValid(t)
	edited, err := d.Edit("Revised description.", "Revised remediation.", tClock.Add(time.Minute))
	if err != nil {
		t.Fatalf("edit proposed: %v", err)
	}
	if edited.Description != "Revised description." || edited.Remediation != "Revised remediation." {
		t.Errorf("edit did not replace text: %+v", edited)
	}
	if !edited.UpdatedAt.After(d.UpdatedAt) {
		t.Error("edit should advance UpdatedAt")
	}
	if edited.ProposedBy != d.ProposedBy {
		t.Error("edit must preserve proposer attribution")
	}

	accepted, err := edited.Accept("user:reviewer", tClock.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := accepted.Edit("late edit", "", tClock); !errors.Is(err, shared.ErrValidation) {
		t.Error("editing an accepted draft must fail")
	}
	// An edit that empties both fields is rejected.
	if _, err := edited.Edit("  ", "", tClock); !errors.Is(err, shared.ErrValidation) {
		t.Error("emptying a draft via Edit must fail")
	}
}

func TestAcceptSignOff(t *testing.T) {
	d := proposeValid(t)
	acc, err := d.Accept("user:reviewer", tClock.Add(time.Minute))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if acc.State != StateAccepted || acc.DecidedBy != "user:reviewer" {
		t.Errorf("accept wrong: state=%q decidedBy=%q", acc.State, acc.DecidedBy)
	}
	// Terminal: cannot re-accept or reject.
	if _, err := acc.Accept("user:other", tClock); !errors.Is(err, shared.ErrValidation) {
		t.Error("re-accepting a decided draft must fail")
	}
	if _, err := acc.Reject("user:other", tClock); !errors.Is(err, shared.ErrValidation) {
		t.Error("rejecting an accepted draft must fail")
	}
}

func TestAcceptSeparationOfDuties(t *testing.T) {
	d := proposeValid(t) // ProposedBy = "agent:writer"
	if _, err := d.Accept("agent:writer", tClock.Add(time.Minute)); !errors.Is(err, shared.ErrValidation) {
		t.Error("the proposer must not be able to sign off its own draft (SoD)")
	}
	if _, err := d.Accept("  ", tClock.Add(time.Minute)); !errors.Is(err, shared.ErrValidation) {
		t.Error("an unattributed acceptance must fail")
	}
}

func TestReject(t *testing.T) {
	d := proposeValid(t)
	rej, err := d.Reject("user:reviewer", tClock.Add(time.Minute))
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rej.State != StateRejected || rej.DecidedBy != "user:reviewer" {
		t.Errorf("reject wrong: %+v", rej)
	}
}

func TestStateValid(t *testing.T) {
	for _, s := range []State{StateProposed, StateAccepted, StateRejected} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []State{"", "confirmed", "draft", "PROPOSED"} {
		if State(s).Valid() {
			t.Errorf("%q should be invalid", s)
		}
	}
}
