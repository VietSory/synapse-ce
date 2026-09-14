package main

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cliRecordingDecorator struct {
	calls int
	got   ports.PRDecoration
	err   error
}

func (f *cliRecordingDecorator) Decorate(_ context.Context, d ports.PRDecoration) error {
	f.calls++
	f.got = d
	return f.err
}

func TestTriggerGateDecorationFromEnv(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "17")
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
	t.Setenv("CI_PROJECT_PATH", "acme/widget")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "head-sha")
	fake := &cliRecordingDecorator{}
	loc := &finding.SourceLocation{File: "src/app.go", StartLine: 12, EndLine: 12}
	findings := []finding.Finding{{
		DedupKey: "cq:test:src/app.go:12", RuleKey: "test-rule", Title: "test finding", Description: "details",
		Kind: finding.KindQuality, Severity: shared.SeverityHigh, SourceLocation: loc,
	}}
	result := qualitygate.Result{Passed: false}

	triggerGateDecorationFromEnv(context.Background(), fake, result, "summary", findings)
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
	if fake.got.Target.Repository != "acme/widget" || fake.got.Target.PullRequest != "17" || fake.got.Target.TargetBranch != "main" || fake.got.Target.CommitSHA != "head-sha" {
		t.Fatalf("target = %+v", fake.got.Target)
	}
	if len(fake.got.Annotations) != 1 || fake.got.Annotations[0].Location.File != "src/app.go" || fake.got.Annotations[0].Location.StartLine != 12 {
		t.Fatalf("annotations = %+v", fake.got.Annotations)
	}
}

func TestTriggerGateDecorationIsFailSoft(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "17")
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
	t.Setenv("CI_PROJECT_PATH", "acme/widget")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "head-sha")
	fake := &cliRecordingDecorator{err: errors.New("forge unavailable")}
	triggerGateDecorationFromEnv(context.Background(), fake, qualitygate.Result{Passed: true}, "summary", nil)
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
}
