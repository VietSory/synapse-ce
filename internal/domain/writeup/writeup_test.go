package writeup

import "testing"

func TestCatalogIntegrity(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, w := range cat {
		if w.ID == "" || w.Title == "" || w.Description == "" || w.Remediation == "" {
			t.Errorf("writeup %q has an empty required field", w.ID)
		}
		if !w.Severity.Valid() {
			t.Errorf("writeup %q has invalid severity %q", w.ID, w.Severity)
		}
		if seen[w.ID] {
			t.Errorf("duplicate writeup id %q", w.ID)
		}
		seen[w.ID] = true
	}
}

func TestGet(t *testing.T) {
	w, ok := Get("sqli")
	if !ok || w.CWE != "CWE-89" {
		t.Fatalf("Get(sqli) = %+v, %v", w, ok)
	}
	if _, ok := Get("does-not-exist"); ok {
		t.Error("Get of unknown id should return ok=false")
	}
}

// Catalog must not share mutable state between calls (callers get a fresh copy).
func TestCatalogIsolated(t *testing.T) {
	a := Catalog()
	if len(a[0].References) > 0 {
		a[0].References[0] = "MUTATED"
	}
	b := Catalog()
	if len(b[0].References) > 0 && b[0].References[0] == "MUTATED" {
		t.Error("Catalog() leaks mutable shared reference data")
	}
}
