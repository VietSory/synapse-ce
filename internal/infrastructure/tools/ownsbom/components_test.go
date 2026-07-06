package ownsbom

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// TestComponentSet locks the shared dedup/emit contract every parser relies on: dedup by PURL identity,
// drop any component missing a name / version / PURL, preserve insertion order.
func TestComponentSet(t *testing.T) {
	s := newComponentSet()
	s.add(sbom.Component{Name: "a", Version: "1", PURL: "pkg:x/a@1"})
	s.add(sbom.Component{Name: "a", Version: "1", PURL: "pkg:x/a@1"})     // duplicate PURL -> dropped
	s.add(sbom.Component{Name: "b", Version: "2", PURL: "pkg:x/b@2"})     //
	s.add(sbom.Component{Name: "", Version: "3", PURL: "pkg:x/c@3"})      // no name -> dropped
	s.add(sbom.Component{Name: "d", Version: "", PURL: "pkg:x/d@"})       // no version -> dropped
	s.add(sbom.Component{Name: "e", Version: "5", PURL: ""})              // no PURL -> dropped
	s.add(sbom.Component{Name: "a", Version: "1.1", PURL: "pkg:x/a@1.1"}) // same name, different version -> kept

	got := s.components()
	if len(got) != 3 {
		t.Fatalf("want 3 components, got %d: %+v", len(got), got)
	}
	if got[0].PURL != "pkg:x/a@1" || got[1].PURL != "pkg:x/b@2" || got[2].PURL != "pkg:x/a@1.1" {
		t.Errorf("dedup/order wrong: %+v", got)
	}
}
