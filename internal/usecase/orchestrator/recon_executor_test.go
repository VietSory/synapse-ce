package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// fakeReconSvc is a reconStarter: Start records the call + returns a queued run; Get returns a
// preset terminal run (so the executor's await loop exits on the first poll, no real sleep).
type fakeReconSvc struct {
	startErr                                 error
	result                                   drecon.Run
	startedActor, startedTool, startedTarget string
	starts                                   int
}

func (f *fakeReconSvc) Start(_ context.Context, actor string, eng shared.ID, tool, target string) (drecon.Run, error) {
	f.starts++
	f.startedActor, f.startedTool, f.startedTarget = actor, tool, target
	if f.startErr != nil {
		return drecon.Run{}, f.startErr
	}
	return drecon.Run{ID: "run-1", EngagementID: eng, Tool: tool, Target: target, Status: drecon.StatusQueued}, nil
}
func (f *fakeReconSvc) Get(_ context.Context, _ shared.ID) (drecon.Run, error) { return f.result, nil }

type fakeEvList struct{ items []evdom.Evidence }

func (f fakeEvList) List(_ context.Context, _ shared.ID) ([]evdom.Evidence, error) {
	return f.items, nil
}

// admitReconProposal builds a real gate (auto mode, in-scope engagement) and admits an
// in-scope subfinder proposal, returning the AdmittedAction the executor must consume.
func admitReconProposal(t *testing.T) safety.AdmittedAction {
	t.Helper()
	now := time.Unix(1_000_000, 0).UTC()
	clk := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, clk, audit)
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approval.NewService(memory.NewApprovalStore(), audit, clk, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clk, ids)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	prop := agent.ProposedAction{
		ID: ids.NewID(), SessionID: "s1", EngagementID: "eng-1",
		Tool: "start_recon", Action: "recon.subfinder",
		Target: engagement.Target{Kind: engagement.TargetDomain, Value: "app.acme.io"},
		Argv:   []string{"subfinder", "-silent", "-d", "app.acme.io"},
		Risk:   agent.RiskActive, ProposedAt: now,
	}
	adm, err := gate.Admit(context.Background(), prop, "alice")
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	return adm
}

func TestReconExecutorRunsAndRecoversOutput(t *testing.T) {
	adm := admitReconProposal(t)
	rec := &fakeReconSvc{result: drecon.Run{ID: "run-1", EngagementID: "eng-1", Status: drecon.StatusSucceeded, ResultCount: 2, EvidenceID: "ev-7"}}
	evl := fakeEvList{items: []evdom.Evidence{{ID: "ev-7", Kind: "terminal_log", Content: []byte("a.app.acme.io\nb.app.acme.io")}}}
	exec, err := orchestrator.NewReconExecutor(rec, evl, fixedClock{time.Unix(1_000_000, 0).UTC()}, time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := exec.Execute(context.Background(), adm)
	if err != nil {
		t.Fatal(err)
	}
	if rec.startedTool != "subfinder" || rec.startedTarget != "app.acme.io" || rec.startedActor != "agent:s1" {
		t.Fatalf("recon started wrong: tool=%s target=%s actor=%s", rec.startedTool, rec.startedTarget, rec.startedActor)
	}
	if !strings.Contains(obs.Summary, "2 in-scope") {
		t.Errorf("summary should report the result count, got %q", obs.Summary)
	}
	if !strings.Contains(string(obs.Output), "a.app.acme.io") {
		t.Errorf("output should be recovered from the sealed terminal_log, got %q", string(obs.Output))
	}
}

func TestReconExecutorFailedRunIsFedBackNotFatal(t *testing.T) {
	adm := admitReconProposal(t)
	rec := &fakeReconSvc{result: drecon.Run{ID: "run-1", Status: drecon.StatusFailed, Stage: "run", Error: "tool crashed"}}
	exec, _ := orchestrator.NewReconExecutor(rec, fakeEvList{}, fixedClock{time.Unix(1_000_000, 0).UTC()}, time.Millisecond, time.Second)
	obs, err := exec.Execute(context.Background(), adm)
	if err != nil {
		t.Fatalf("a tool-level failure must be fed back, not returned as an error: %v", err)
	}
	if !strings.Contains(obs.Summary, "failed") || !strings.Contains(string(obs.Output), "tool crashed") {
		t.Errorf("failure should be summarized + fed back, got summary=%q output=%q", obs.Summary, string(obs.Output))
	}
}

func TestReconExecutorStartErrorFedBack(t *testing.T) {
	adm := admitReconProposal(t)
	rec := &fakeReconSvc{startErr: errors.New("live recon is not enabled")}
	exec, _ := orchestrator.NewReconExecutor(rec, fakeEvList{}, fixedClock{time.Unix(1_000_000, 0).UTC()}, time.Millisecond, time.Second)
	obs, err := exec.Execute(context.Background(), adm)
	if err != nil {
		t.Fatalf("a start refusal must be fed back, not fatal: %v", err)
	}
	if !strings.Contains(obs.Summary, "could not start") {
		t.Errorf("start refusal should be summarized, got %q", obs.Summary)
	}
}

func TestNewReconExecutorValidates(t *testing.T) {
	if _, err := orchestrator.NewReconExecutor(nil, fakeEvList{}, fixedClock{}, 0, 0); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil recon must fail validation")
	}
}
