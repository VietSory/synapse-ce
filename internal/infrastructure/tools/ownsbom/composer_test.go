package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const composerLockFixture = `{
  "packages": [
    {"name": "symfony/console", "version": "v6.3.0"},
    {"name": "monolog/monolog", "version": "3.4.0"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.3.1"}
  ]
}`

func TestComposerParse(t *testing.T) {
	comps, deps, err := Composer{}.Parse(context.Background(), ParseInput{Path: "composer.lock", Content: []byte(composerLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges deferred; want nil deps, got %v", deps)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d (%+v)", len(comps), comps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if c := byName["symfony/console"]; c.PURL != "pkg:composer/symfony/console@v6.3.0" {
		t.Errorf("vendor/package PURL wrong: %+v", c)
	}
	if c := byName["symfony/console"]; c.Scope == sbom.ScopeDevelopment {
		t.Errorf("a production package must not be development-scoped: %+v", c)
	}
	if d := byName["phpunit/phpunit"]; d.Scope != sbom.ScopeDevelopment || d.PURL != "pkg:composer/phpunit/phpunit@10.3.1" {
		t.Errorf("a packages-dev entry must be development-scoped: %+v", d)
	}
}

func TestComposerParseMalformed(t *testing.T) {
	if _, _, err := (Composer{}).Parse(context.Background(), ParseInput{Path: "composer.lock", Content: []byte("{not json")}); err == nil {
		t.Error("malformed composer.lock must fail loud")
	}
}

func TestComposerParseEmpty(t *testing.T) {
	comps, _, err := Composer{}.Parse(context.Background(), ParseInput{Path: "composer.lock", Content: []byte(`{"packages":[],"packages-dev":[]}`)})
	if err != nil || len(comps) != 0 {
		t.Errorf("empty lock → no components, no error; got %d comps, err=%v", len(comps), err)
	}
}
