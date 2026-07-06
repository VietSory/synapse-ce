package advisoryingest

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeFeed yields a fixed set of advisories and reports a fixed skip count.
type fakeFeed struct {
	advs    []advisory.Advisory
	skipped int
}

func (f fakeFeed) Each(_ context.Context, fn func(advisory.Advisory) error) (int, error) {
	for _, a := range f.advs {
		if err := fn(a); err != nil {
			return f.skipped, err
		}
	}
	return f.skipped, nil
}

// fakeWriter records upserts; failAt makes the Nth (1-based) upsert fail.
type fakeWriter struct {
	got    []string
	failAt int
}

func (w *fakeWriter) Upsert(_ context.Context, a advisory.Advisory) error {
	w.got = append(w.got, a.ID)
	if w.failAt != 0 && len(w.got) == w.failAt {
		return errors.New("boom")
	}
	return nil
}

func a(id string) advisory.Advisory { return advisory.Advisory{ID: id} }

func TestIngestUpsertsAllAndCountsSkips(t *testing.T) {
	w := &fakeWriter{}
	s, err := NewService(fakeFeed{advs: []advisory.Advisory{a("CVE-1"), a("CVE-2")}, skipped: 3}, w)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.Ingest(context.Background())
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if st.Ingested != 2 || st.Skipped != 3 {
		t.Fatalf("want ingested=2 skipped=3, got %+v", st)
	}
	if len(w.got) != 2 || w.got[0] != "CVE-1" || w.got[1] != "CVE-2" {
		t.Fatalf("upserts wrong: %v", w.got)
	}
}

// A store write failure is FATAL: the run aborts with the partial Stats and the error (a half-loaded corpus
// that swallowed write errors would silently under-report vulnerabilities).
func TestIngestStoreErrorIsFatal(t *testing.T) {
	w := &fakeWriter{failAt: 2}
	s, _ := NewService(fakeFeed{advs: []advisory.Advisory{a("CVE-1"), a("CVE-2"), a("CVE-3")}}, w)
	st, err := s.Ingest(context.Background())
	if err == nil {
		t.Fatal("a store write failure must abort the ingest")
	}
	if st.Ingested != 1 {
		t.Fatalf("want 1 ingested before the fatal write, got %d", st.Ingested)
	}
	if len(w.got) != 2 { // attempted CVE-1 (ok) + CVE-2 (failed); never reached CVE-3
		t.Fatalf("must stop at the failing upsert, got %v", w.got)
	}
}

// An id-less advisory from the feed is skipped (defense-in-depth), not a fatal write.
func TestIngestSkipsIDlessAdvisory(t *testing.T) {
	w := &fakeWriter{}
	s, _ := NewService(fakeFeed{advs: []advisory.Advisory{a(""), a("CVE-2")}}, w)
	st, err := s.Ingest(context.Background())
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if st.Ingested != 1 || st.Skipped != 1 || len(w.got) != 1 {
		t.Fatalf("id-less advisory must be skipped: %+v upserts=%v", st, w.got)
	}
}

func TestNewServiceValidates(t *testing.T) {
	if _, err := NewService(nil, &fakeWriter{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil feed must fail: %v", err)
	}
	if _, err := NewService(fakeFeed{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil writer must fail: %v", err)
	}
}
