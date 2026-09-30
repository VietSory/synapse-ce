package scmwebhook

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeBindingReader struct {
	bindings []integration.Binding
	err      error
}

func (f *fakeBindingReader) ListIntegrationBindings(context.Context, shared.ID) ([]integration.Binding, error) {
	return append([]integration.Binding(nil), f.bindings...), f.err
}

type webhookScanCall struct {
	actor, ref, sha string
	tenant, project shared.ID
	fork            bool
}

type fakeProjectScanner struct {
	calls []webhookScanCall
	err   error
}

func (f *fakeProjectScanner) StartWebhookAnalysis(_ context.Context, actor string, tenant, project shared.ID, ref, sha string, fork bool) (ports.ScanJob, error) {
	f.calls = append(f.calls, webhookScanCall{actor: actor, tenant: tenant, project: project, ref: ref, sha: sha, fork: fork})
	return ports.ScanJob{}, f.err
}

func gitLabIdentity() ports.InboundWebhookIdentity {
	return ports.InboundWebhookIdentity{PublicID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TenantID: "tenant", OwnerKind: "integration", OwnerID: "gitlab-hook"}
}

func TestGitLabPushRoutesOnlyBoundProjectAndIgnoresPayloadURL(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver, err := NewReceiver(bindings, scans)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{
		"ref":"refs/heads/main",
		"checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"project":{"git_http_url":"https://attacker.example/evil.git"},
		"repository":{"url":"https://attacker.example/evil.git"}
	}`)
	err = receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "event", Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls = %d, want 1", len(scans.calls))
	}
	got := scans.calls[0]
	if got.tenant != "tenant" || got.project != "project-1" || got.ref != "main" ||
		got.sha != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || got.fork {
		t.Fatalf("unexpected scan call: %#v", got)
	}
}

func TestGitLabForkMergeRequestDisablesBuildExecutionAtProjectBoundary(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver, _ := NewReceiver(bindings, scans)
	body := []byte(`{
		"object_attributes":{
			"source_branch":"fork/feature",
			"source_project_id":22,
			"target_project_id":11,
			"last_commit":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			"source":{"git_http_url":"https://fork.example/never-used.git"},
			"target":{"git_http_url":"https://target.example/also-not-used.git"}
		}
	}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Merge Request Hook", EventID: "event", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 || !scans.calls[0].fork {
		t.Fatalf("fork MR scan = %#v", scans.calls)
	}
	if scans.calls[0].ref != "fork/feature" || scans.calls[0].sha != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("fork target = %#v", scans.calls[0])
	}
}

func TestGitLabReceiverFailsClosedOnAmbiguousBindingOrInvalidSHA(t *testing.T) {
	scans := &fakeProjectScanner{}
	multi := &fakeBindingReader{bindings: []integration.Binding{
		{IntegrationID: "gitlab-hook", ProjectID: "project-1"},
		{IntegrationID: "gitlab-hook", ProjectID: "project-2"},
	}}
	receiver, _ := NewReceiver(multi, scans)
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", Body: body,
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("ambiguous binding error = %v, want conflict", err)
	}

	single := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	receiver, _ = NewReceiver(single, scans)
	bad := []byte(`{"ref":"refs/heads/main","checkout_sha":"NOT-A-SHA"}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", Body: bad,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid sha error = %v, want validation", err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("invalid/ambiguous event started scans: %#v", scans.calls)
	}
}

func TestGitLabUnsupportedAndDeleteEventsAreNoOps(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver, _ := NewReceiver(bindings, scans)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Pipeline Hook", Body: []byte(`{"url":"https://attacker.example"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook",
		Body: []byte(`{"ref":"refs/heads/deleted","checkout_sha":null,"after":"0000000000000000000000000000000000000000"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("no-op events started scans: %#v", scans.calls)
	}
}
