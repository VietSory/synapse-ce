package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const swiftV2Fixture = `{
  "pins": [
    {"identity": "alamofire", "kind": "remoteSourceControl", "location": "https://github.com/Alamofire/Alamofire", "state": {"version": "5.6.4"}},
    {"identity": "swift-log", "state": {"version": "1.5.2"}},
    {"identity": "local-branch", "state": {"branch": "main", "revision": "abc123"}}
  ],
  "version": 2
}`

const swiftV1Fixture = `{
  "object": {
    "pins": [
      {"package": "Alamofire", "state": {"version": "5.6.4"}}
    ]
  },
  "version": 1
}`

func TestSwiftParseV2(t *testing.T) {
	comps, deps, err := Swift{}.Parse(context.Background(), ParseInput{Path: "Package.resolved", Content: []byte(swiftV2Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges not emitted; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// alamofire + swift-log have versions; local-branch (a branch pin, no resolved version) is skipped.
	if len(comps) != 2 {
		t.Fatalf("want 2 versioned components, got %d (%+v)", len(comps), comps)
	}
	if c := byName["alamofire"]; c.PURL != "pkg:swift/alamofire@5.6.4" {
		t.Errorf("v2 identity-keyed PURL wrong: %+v", c)
	}
	if _, ok := byName["local-branch"]; ok {
		t.Error("a branch pin with no resolved version must be skipped")
	}
}

func TestSwiftParseV1(t *testing.T) {
	comps, _, err := Swift{}.Parse(context.Background(), ParseInput{Path: "Package.resolved", Content: []byte(swiftV1Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || comps[0].PURL != "pkg:swift/Alamofire@5.6.4" {
		t.Fatalf("v1 object.pins layout: want 1 component pkg:swift/Alamofire@5.6.4, got %+v", comps)
	}
}

func TestSwiftParseMalformed(t *testing.T) {
	if _, _, err := (Swift{}).Parse(context.Background(), ParseInput{Path: "Package.resolved", Content: []byte("{bad")}); err == nil {
		t.Error("malformed Package.resolved must fail loud")
	}
}
