package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestVisitRawSecretRecoversOnlyExactReportedCandidate(t *testing.T) {
	root := t.TempDir()
	token := "ghp_" + strings.Repeat("aB3dE6", 7)
	if err := os.WriteFile(filepath.Join(root, "app.env"), []byte("name=x\ntoken = \""+token+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := New()
	report, err := scanner.ScanFiles(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var hit ports.SecretRawFinding
	for _, candidate := range report.Findings {
		if candidate.RuleID == "github-token" {
			hit = candidate
			break
		}
	}
	if hit.RuleID == "" {
		t.Fatalf("github hit not found: %#v", report.Findings)
	}
	if strings.Contains(hit.Match, token) {
		t.Fatal("base scanner leaked the raw credential")
	}
	var recovered string
	found, err := scanner.VisitRawSecret(context.Background(), root, hit, func(raw string) error {
		recovered = raw
		return nil
	})
	if err != nil || !found || recovered != token {
		t.Fatalf("found=%v recovered=%q err=%v", found, recovered, err)
	}

	wrong := hit
	wrong.Line++
	called := false
	found, err = scanner.VisitRawSecret(context.Background(), root, wrong, func(string) error { called = true; return nil })
	if err != nil || found || called {
		t.Fatalf("wrong-line recovery found=%v called=%v err=%v", found, called, err)
	}
}

func TestVisitRawSecretRefusesHistoryAndTraversal(t *testing.T) {
	scanner := New()
	root := t.TempDir()
	for _, hit := range []ports.SecretRawFinding{
		{File: "app.env", Line: 1, RuleID: "github-token", FromHistory: true},
		{File: "../outside.env", Line: 1, RuleID: "github-token"},
	} {
		called := false
		found, err := scanner.VisitRawSecret(context.Background(), root, hit, func(string) error { called = true; return nil })
		if err != nil || found || called {
			t.Fatalf("hit=%#v found=%v called=%v err=%v", hit, found, called, err)
		}
	}
}
