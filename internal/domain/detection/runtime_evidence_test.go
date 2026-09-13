package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuntimeEvidenceKindsArePositiveAndDistinct(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	base := RuntimeEvidence{
		At: at, Host: "host-1", PID: 42, UID: 1000, Comm: "app",
		Path: "/usr/lib/libexample.so.1", Device: 2049, Inode: 99,
	}

	for _, kind := range []RuntimeEvidenceKind{
		RuntimeEvidenceBinaryExec,
		RuntimeEvidenceLibraryLoaded,
		RuntimeEvidenceSymbolHit,
	} {
		t.Run(string(kind), func(t *testing.T) {
			ev := base
			ev.Kind = kind
			if kind == RuntimeEvidenceSymbolHit {
				ev.Symbol = "example_vulnerable"
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("valid %s evidence rejected: %v", kind, err)
			}
		})
	}

	if RuntimeEvidenceBinaryExec == RuntimeEvidenceLibraryLoaded ||
		RuntimeEvidenceLibraryLoaded == RuntimeEvidenceSymbolHit ||
		RuntimeEvidenceBinaryExec == RuntimeEvidenceSymbolHit {
		t.Fatal("runtime evidence kinds must remain distinct")
	}
}

func TestRuntimeEvidenceRejectsNegativeOrAmbiguousEvidence(t *testing.T) {
	valid := RuntimeEvidence{
		Kind: RuntimeEvidenceLibraryLoaded,
		At:   time.Unix(100, 0).UTC(), Host: "host-1", PID: 42,
		Path: "/usr/lib/libexample.so.1", Device: 2049, Inode: 99,
	}

	tests := []struct {
		name   string
		mutate func(*RuntimeEvidence)
	}{
		{name: "unknown kind", mutate: func(e *RuntimeEvidence) { e.Kind = "not_reachable" }},
		{name: "missing timestamp", mutate: func(e *RuntimeEvidence) { e.At = time.Time{} }},
		{name: "missing host", mutate: func(e *RuntimeEvidence) { e.Host = shared.ID("") }},
		{name: "missing pid", mutate: func(e *RuntimeEvidence) { e.PID = 0 }},
		{name: "missing path", mutate: func(e *RuntimeEvidence) { e.Path = "" }},
		{name: "missing inode", mutate: func(e *RuntimeEvidence) { e.Inode = 0 }},
		{name: "weak evidence carrying symbol", mutate: func(e *RuntimeEvidence) { e.Symbol = "must-not-upgrade" }},
		{name: "symbol hit missing symbol", mutate: func(e *RuntimeEvidence) {
			e.Kind = RuntimeEvidenceSymbolHit
			e.Symbol = ""
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := valid
			tt.mutate(&ev)
			if err := ev.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}
