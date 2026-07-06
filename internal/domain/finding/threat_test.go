package finding

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewThreat(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f, err := NewThreat("f1", "eng-1", ThreatInput{
		JudgmentID: "j-1", Category: "info_disclosure", Element: "f1-flow", Asset: "pii",
	}, now)
	if err != nil {
		t.Fatalf("NewThreat: %v", err)
	}
	if f.Kind != KindThreat || f.Class != ClassFirstParty || f.Status != StatusOpen {
		t.Fatalf("wrong kind/class/status: %+v", f)
	}
	if f.Title != "STRIDE info_disclosure threat on f1-flow" {
		t.Errorf("title not templated: %q", f.Title)
	}
	if f.DedupKey != "threat:j-1" {
		t.Errorf("dedup key must anchor the source judgment: %q", f.DedupKey)
	}
	if f.Severity != shared.SeverityUnknown {
		t.Errorf("severity must default to Unknown (human triages), got %q", f.Severity)
	}
	if f.Description == "" || !contains(f.Description, "pii") {
		t.Errorf("asset at risk should appear in the description: %q", f.Description)
	}
}

func TestNewThreatCustomSeverity(t *testing.T) {
	f, err := NewThreat("f1", "eng-1", ThreatInput{JudgmentID: "j", Category: "tampering", Element: "db", Severity: shared.SeverityHigh}, time.Unix(1, 0))
	if err != nil || f.Severity != shared.SeverityHigh {
		t.Fatalf("explicit severity must be honored: sev=%q err=%v", f.Severity, err)
	}
}

func TestNewThreatRejectsIncomplete(t *testing.T) {
	cases := []struct {
		name string
		in   ThreatInput
	}{
		{"no category", ThreatInput{JudgmentID: "j", Element: "x"}},
		{"no element", ThreatInput{JudgmentID: "j", Category: "spoofing"}},
		{"no judgment anchor", ThreatInput{Category: "spoofing", Element: "x"}},
		{"bad severity", ThreatInput{JudgmentID: "j", Category: "spoofing", Element: "x", Severity: "nope"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewThreat("f1", "eng-1", c.in, time.Unix(1, 0)); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s must be rejected with ErrValidation, got %v", c.name, err)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
