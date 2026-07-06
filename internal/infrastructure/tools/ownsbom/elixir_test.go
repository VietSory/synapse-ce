package ownsbom

import (
	"context"
	"testing"
)

const mixLock = `%{
  "bandit": {:hex, :bandit, "1.5.7", "hashA", [:mix], [{:hpax, "~> 0.2", [hex: :hpax, optional: false]}], "hexpm", "hashB"},
  "phoenix": {:hex, :phoenix, "1.7.14", "hashC", [:mix], [], "hexpm", "hashD"},
  "local_dep": {:path, "../local", []},
  "git_dep": {:git, "https://example.com/x.git", "abc123", []},
}
`

func TestElixirParseMixLock(t *testing.T) {
	comps, deps, err := (Elixir{}).Parse(context.Background(), ParseInput{Path: "mix.lock", Content: []byte(mixLock)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if deps != nil {
		t.Errorf("mix.lock yields components, not edges; got %+v", deps)
	}
	got := map[string]string{}
	purl := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		purl[c.Name] = c.PURL
	}
	if got["bandit"] != "1.5.7" || got["phoenix"] != "1.7.14" {
		t.Errorf("hex deps not parsed: %v", got)
	}
	if purl["phoenix"] != "pkg:hex/phoenix@1.7.14" {
		t.Errorf("hex PURL wrong: %q", purl["phoenix"])
	}
	//:path and:git deps are not Hex packages → not cataloged.
	if _, ok := got["local_dep"]; ok {
		t.Error(":path dep must be skipped (no Hex version)")
	}
	if _, ok := got["git_dep"]; ok {
		t.Error(":git dep must be skipped (no Hex version)")
	}
	if len(comps) != 2 {
		t.Errorf("want exactly 2 hex components, got %d", len(comps))
	}
}

func TestElixirMarkersAndEcosystem(t *testing.T) {
	e := Elixir{}
	if e.Ecosystem() != "hex" {
		t.Errorf("Ecosystem() = %q, want hex", e.Ecosystem())
	}
	if len(e.Markers()) != 1 || e.Markers()[0] != "mix.lock" {
		t.Errorf("Markers() = %v, want [mix.lock]", e.Markers())
	}
}

func TestDefaultRegistryIncludesElixir(t *testing.T) {
	r, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	if _, ok := r.byMarker["mix.lock"]; !ok {
		t.Error("the default registry must claim mix.lock (Elixir/Hex coverage)")
	}
}
