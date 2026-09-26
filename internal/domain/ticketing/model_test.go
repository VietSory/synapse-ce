package ticketing

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestLinkRefusesCredentialBearingURLs(t *testing.T) {
	invalid := []string{
		"http://jira.example/browse/SEC-1",
		"https://user:secret@jira.example/browse/SEC-1",
		"https://jira.example/browse/SEC-1?token=secret",
		"https://jira.example/browse/SEC-1#token",
		"https://jira.example/browse/SEC-1?",
		"https://",
		"https://jira.example/browse/SEC-1" + strings.Repeat("a", 2050),
	}
	for _, candidate := range invalid {
		if _, err := CanonicalURL(candidate); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("accepted invalid link: %q", candidate)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("URL validator disclosed a rejected credential")
		}
	}
	if got, err := CanonicalURL(" https://jira.example/browse/SEC-1 "); err != nil || got != "https://jira.example/browse/SEC-1" {
		t.Fatalf("canonicalize URL: %q %v", got, err)
	}
	manual := Link{ID: "link-a", TenantID: "tenant-a", EngagementID: "eng-a", FindingID: "finding-a",
		ExternalURL: "https://jira.example/browse/SEC-1", ExternalID: "SEC-1", CreatedAt: time.Now()}
	if err := manual.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("manual link claimed provider ID: %v", err)
	}
	manual.ExternalID = ""
	if err := manual.Validate(); err != nil {
		t.Fatal(err)
	}
}
