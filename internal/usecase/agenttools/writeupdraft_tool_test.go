package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
)

type fakeWriteupdraftProposer struct {
	got writeupdraft.Draft
	err error
}

func (f *fakeWriteupdraftProposer) Propose(_ context.Context, proposer string, eng, findingID shared.ID, description, remediation string) (writeupdraft.Draft, error) {
	if f.err != nil {
		return writeupdraft.Draft{}, f.err
	}
	// echo a PROPOSED draft, mirroring writeupdraftuc.Propose (which validates + persists + audits)
	f.got = writeupdraft.Draft{
		ID: "wd-1", EngagementID: eng, FindingID: findingID,
		Description: description, Remediation: remediation,
		State: writeupdraft.StateProposed, ProposedBy: proposer,
	}
	return f.got, nil
}

func TestProposeWriteupDraftDisabledByDefault(t *testing.T) {
	c, _ := newCatalog(t, nil, nil)
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeWriteupDraft {
			t.Fatal("propose_writeup_draft must NOT be advertised until EnableWriteupDrafts")
		}
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeWriteupDraft, Arguments: json.RawMessage(`{"finding_id":"f1","description":"x"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("disabled tool must fail closed with ErrValidation, got %v", err)
	}
}

func TestProposeWriteupDraft(t *testing.T) {
	c, _ := newCatalog(t, nil, nil)
	fp := &fakeWriteupdraftProposer{}
	c.EnableWriteupDrafts(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeWriteupDraft {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_writeup_draft has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_writeup_draft must be advertised after EnableWriteupDrafts")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeWriteupDraft,
		Arguments: json.RawMessage(`{"finding_id":"f1","description":"SQLi in login","remediation":"use parameterized queries"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// recorded as PROPOSED, attributed to the AGENT, scoped to the SESSION engagement, for the requested finding
	if fp.got.State != writeupdraft.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed + agent actor: %+v", fp.got)
	}
	if fp.got.EngagementID != "eng-1" || fp.got.FindingID != "f1" {
		t.Fatalf("scope wiring wrong (engagement must be the session's, never from args): %+v", fp.got)
	}
	if fp.got.Description != "SQLi in login" || fp.got.Remediation != "use parameterized queries" {
		t.Fatalf("prose not passed through: %+v", fp.got)
	}
	if !json.Valid(res.Data) {
		t.Error("result payload must be valid JSON")
	}
}

func TestProposeWriteupDraftRequiresFindingID(t *testing.T) {
	c, _ := newCatalog(t, nil, nil)
	c.EnableWriteupDrafts(&fakeWriteupdraftProposer{})
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeWriteupDraft, Arguments: json.RawMessage(`{"description":"x"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing finding_id must fail with ErrValidation, got %v", err)
	}
}
