package advisory

import "testing"

func TestAdvisoryMatch(t *testing.T) {
	adv := Advisory{
		ID:      "GHSA-xxxx",
		Aliases: []string{"CVE-2024-1"},
		Affected: []AffectedPackage{
			{
				Ecosystem: "Go", Package: "github.com/foo/bar",
				Ranges:       semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"}),
				FixedVersion: "1.2.0",
			},
		},
	}
	// affected within the range -> matched, with the block's fixed version
	if ok, fixed := adv.Match("Go", "github.com/foo/bar", "1.1.0"); !ok || fixed != "1.2.0" {
		t.Errorf("want matched with fixed 1.2.0, got ok=%v fixed=%q", ok, fixed)
	}
	// at the fixed version -> not affected
	if ok, _ := adv.Match("Go", "github.com/foo/bar", "1.2.0"); ok {
		t.Error("1.2.0 (== fixed) must not match")
	}
	// right package, WRONG ecosystem -> no match (no cross-ecosystem false hit)
	if ok, _ := adv.Match("npm", "github.com/foo/bar", "1.1.0"); ok {
		t.Error("a different ecosystem must not match")
	}
	// wrong package -> no match
	if ok, _ := adv.Match("Go", "github.com/other/pkg", "1.1.0"); ok {
		t.Error("a different package must not match")
	}
}
