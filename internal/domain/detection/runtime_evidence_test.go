package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuntimeEvidenceKindsStayDistinct(t *testing.T) {
	if RuntimeEvidenceBinaryExec == RuntimeEvidenceLibraryLoaded || RuntimeEvidenceLibraryLoaded == RuntimeEvidenceSymbolHit || RuntimeEvidenceBinaryExec == RuntimeEvidenceSymbolHit {
		t.Fatal("runtime evidence kinds must remain distinct")
	}
	for _, kind := range []RuntimeEvidenceKind{RuntimeEvidenceBinaryExec, RuntimeEvidenceLibraryLoaded, RuntimeEvidenceSymbolHit} {
		if !kind.Valid() {
			t.Fatalf("known runtime kind %q rejected", kind)
		}
	}
}

func TestRuntimeEvidenceValidationIsRaiseOnly(t *testing.T) {
	base := RuntimeEvidence{Kind: RuntimeEvidenceSymbolHit, At: time.Unix(100, 0).UTC(), PID: 42, Path: "/usr/lib/libx.so", Symbol: "vuln", Inode: 7}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid symbol hit rejected: %v", err)
	}
	for _, mutate := range []func(*RuntimeEvidence){
		func(e *RuntimeEvidence) { e.Kind = "not_reachable" },
		func(e *RuntimeEvidence) { e.At = time.Time{} },
		func(e *RuntimeEvidence) { e.PID = 0 },
		func(e *RuntimeEvidence) { e.Path = "" },
		func(e *RuntimeEvidence) { e.Symbol = "" },
		func(e *RuntimeEvidence) { e.Inode = 0 },
	} {
		ev := base
		mutate(&ev)
		if err := ev.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected validation error, got %v for %+v", err, ev)
		}
	}
	weak := RuntimeEvidence{Kind: RuntimeEvidenceLibraryLoaded, At: base.At, PID: 42, Path: "/usr/lib/libx.so"}
	weak.Symbol = "must-not-upgrade"
	if err := weak.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("weak evidence carrying symbol must be rejected, got %v", err)
	}
}
