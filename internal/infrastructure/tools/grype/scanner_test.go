package grype

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const sampleGrype = `{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "severity": "High",
        "description": "bad thing",
        "fix": {"versions": ["1.2.4"], "state": "fixed"},
        "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 7.5}}]
      },
      "relatedVulnerabilities": [{"id": "CVE-2024-1234"}],
      "artifact": {"name": "lodash", "version": "4.17.20"}
    }
  ],
  "descriptor": {"name": "grype", "version": "0.74.0", "db": {"status": {"built": "2026-06-01T00:00:00Z", "schemaVersion": "v6.1.7"}}}
}`

func TestGrypeParseAndMap(t *testing.T) {
	var out grypeOutput
	if err := json.Unmarshal([]byte(sampleGrype), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.dbLabel(); got != "schema-v6.1.7@2026-06-01T00:00:00Z" {
		t.Errorf("dbLabel = %q", got)
	}
	if len(out.Matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(out.Matches))
	}
	r := matchToRaw(out.Matches[0], nil)
	if r.Source != "grype" {
		t.Errorf("source = %q, want grype", r.Source)
	}
	if r.AdvisoryID != "CVE-2024-1234" {
		t.Errorf("AdvisoryID = %q, want the CVE (preferred over GHSA)", r.AdvisoryID)
	}
	if r.Severity != shared.SeverityHigh {
		t.Errorf("severity = %q, want high", r.Severity)
	}
	if r.Component != "lodash" || r.Version != "4.17.20" {
		t.Errorf("component = %q@%q", r.Component, r.Version)
	}
	if r.FixedVersion != "1.2.4" {
		t.Errorf("fixed = %q, want 1.2.4", r.FixedVersion)
	}
	if r.CVSSScore != 7.5 {
		t.Errorf("cvss = %v, want 7.5", r.CVSSScore)
	}
}

func TestGrypeUsesSBOMComponentNameForArtifactPURL(t *testing.T) {
	match := grypeMatch{}
	match.Vulnerability.ID = "CVE-2024-38816"
	match.Artifact.Name = "spring-webmvc"
	match.Artifact.Version = "5.3.39"
	match.Artifact.PURL = "pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar"

	components := map[string]sbom.Component{
		"pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar": {
			Name:    "org.springframework:spring-webmvc",
			Version: "5.3.39",
			PURL:    "pkg:maven/org.springframework/spring-webmvc@5.3.39?type=jar",
		},
	}
	r := matchToRaw(match, components)
	if r.Component != "org.springframework:spring-webmvc" {
		t.Fatalf("component = %q, want canonical SBOM component name", r.Component)
	}
}

// Regression #7: a missing Grype binary degrades gracefully (no error, no crash).
func TestGrypeMissingBinaryDegrades(t *testing.T) {
	s := New("synapse-no-such-grype-binary", "")
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", Version: "1", PURL: "pkg:npm/x@1"}}}
	raws, err := s.Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("missing binary must degrade gracefully (nil error), got %v", err)
	}
	if raws != nil {
		t.Errorf("want no findings when grype is missing, got %d", len(raws))
	}
	if v, db := s.Provenance(); v != "" || db != "" {
		t.Errorf("provenance must be empty when grype unavailable, got %q/%q", v, db)
	}
}

func TestGrypeEmptySBOM(t *testing.T) {
	s := New("grype", "")
	raws, err := s.Scan(context.Background(), &sbom.SBOM{})
	if err != nil || raws != nil {
		t.Fatalf("empty sbom: want nil,nil; got %v,%v", raws, err)
	}
}
