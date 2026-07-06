package distro

import (
	"testing"
	"time"
)

func TestParseTag(t *testing.T) {
	cases := []struct {
		tag    string
		want   Release
		wantOK bool
	}{
		{"debian-9", Release{ID: "debian", Version: "9", Codename: "stretch"}, true},
		{"debian-9.13", Release{ID: "debian", Version: "9", Codename: "stretch"}, true}, // point release → major
		{"alpine-3.18.12", Release{ID: "alpine", Version: "3.18"}, true},                // → major.minor
		{"ubuntu-22.04", Release{ID: "ubuntu", Version: "22.04", Codename: "jammy"}, true},
		{"rhel-9", Release{ID: "rhel", Version: "9"}, true},
		{"", Release{}, false},
		{"debian", Release{}, false}, // no version
		{"-9", Release{}, false},     // no id
	}
	for _, c := range cases {
		got, ok := ParseTag(c.tag)
		if ok != c.wantOK || got != c.want {
			t.Errorf("ParseTag(%q) = %+v,%v want %+v,%v", c.tag, got, ok, c.want, c.wantOK)
		}
	}
}

func TestEvaluateEOL(t *testing.T) {
	asOf := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		id, version string
		wantEOL     bool
		wantKnown   bool
	}{
		{"debian", "9", true, true},     // LTS ended 2022-06-30
		{"debian", "10", true, true},    // LTS ended 2024-06-30
		{"debian", "11", false, true},   // LTS ends 2026-08-31 (after asOf)
		{"alpine", "3.18", true, true},  // ended 2025-05-09
		{"alpine", "3.21", false, true}, // ends 2026-11-01
		{"ubuntu", "20.04", true, true}, // standard support ended 2025-05-31
		{"ubuntu", "22.04", false, true},
		{"centos", "8", true, true},    // early EOL 2021-12-31
		{"debian", "99", false, false}, // unknown release → no claim
		{"plan9", "1", false, false},   // unknown distro → no claim
	}
	for _, c := range cases {
		st := Evaluate(Release{ID: c.id, Version: c.version}, asOf)
		if st.EndOfLife != c.wantEOL || st.Known != c.wantKnown {
			t.Errorf("Evaluate(%s %s) EOL=%v Known=%v want EOL=%v Known=%v", c.id, c.version, st.EndOfLife, st.Known, c.wantEOL, c.wantKnown)
		}
		if c.wantKnown && st.Source == "" {
			t.Errorf("Evaluate(%s %s): known release must cite a source", c.id, c.version)
		}
		if !c.wantKnown && (st.EndOfLife || st.EOLDate != "") {
			t.Errorf("Evaluate(%s %s): unknown release must not assert EOL", c.id, c.version)
		}
	}
}

func TestEvaluateBoundaryIsInclusive(t *testing.T) {
	// On the EOL date itself the release is End-of-Life (asOf >= date).
	onDate := time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC)
	if st := Evaluate(Release{ID: "debian", Version: "9"}, onDate); !st.EndOfLife {
		t.Error("debian 9 must be EOL on its EOL date (boundary inclusive)")
	}
	dayBefore := time.Date(2022, 6, 29, 23, 59, 0, 0, time.UTC)
	if st := Evaluate(Release{ID: "debian", Version: "9"}, dayBefore); st.EndOfLife {
		t.Error("debian 9 must NOT be EOL the day before its EOL date")
	}
}

// TestEOLTableWellFormed: every curated date must be a valid YYYY-MM-DD so a known release always
// yields a real verdict (guards against a typo shipping a date-less "supported" claim).
func TestEOLTableWellFormed(t *testing.T) {
	for key, date := range eolDates {
		if _, err := time.Parse("2006-01-02", date); err != nil {
			t.Errorf("eolDates[%q] = %q is not a valid YYYY-MM-DD: %v", key, date, err)
		}
	}
}

func TestDetectDominant(t *testing.T) {
	// The most frequent parseable tag wins; unparseable tags are ignored.
	tags := []string{"debian-9", "debian-9", "alpine-3.18", "", "garbage"} // "garbage" has no '-' → unparseable
	rel, ok := Detect(tags)
	if !ok || rel.ID != "debian" || rel.Version != "9" {
		t.Fatalf("Detect dominant = %+v,%v want debian 9", rel, ok)
	}
	if _, ok := Detect(nil); ok {
		t.Error("Detect(nil) should be ok=false")
	}
	if _, ok := Detect([]string{"", "garbage"}); ok {
		t.Error("Detect with no parseable tags should be ok=false")
	}
}
