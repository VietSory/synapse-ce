package engagement

import (
	"testing"
	"time"
)

func TestToolClassOf(t *testing.T) {
	cases := map[string]ToolClass{
		"sca.scan":        "sca",
		"recon.subfinder": "recon",
		"exploit":         "exploit",
		"":                "",
		"a.b.c":           "a",
	}
	for action, want := range cases {
		if got := ToolClassOf(action); got != want {
			t.Errorf("ToolClassOf(%q) = %q, want %q", action, got, want)
		}
	}
}

func TestRoEPermits(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	blackout := Blackout{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	cases := []struct {
		name   string
		roe    RoE
		class  ToolClass
		at     time.Time
		wantOK bool
		reason string
	}{
		{"empty allows all", RoE{}, "recon", now, true, ""},
		{"allowed class", RoE{AllowedToolClasses: []ToolClass{"sca", "recon"}}, "recon", now, true, ""},
		{"disallowed class", RoE{AllowedToolClasses: []ToolClass{"sca"}}, "recon", now, false, "tool_not_allowed"},
		{"inside blackout", RoE{Blackouts: []Blackout{blackout}}, "sca", now, false, "blackout_window"},
		{"outside blackout", RoE{Blackouts: []Blackout{blackout}}, "sca", now.Add(2 * time.Hour), true, ""},
		{"class ok but in blackout", RoE{AllowedToolClasses: []ToolClass{"sca"}, Blackouts: []Blackout{blackout}}, "sca", now, false, "blackout_window"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := c.roe.Permits(c.class, c.at)
			if ok != c.wantOK || reason != c.reason {
				t.Errorf("Permits(%q,%v) = (%v,%q), want (%v,%q)", c.class, c.at, ok, reason, c.wantOK, c.reason)
			}
		})
	}
}
