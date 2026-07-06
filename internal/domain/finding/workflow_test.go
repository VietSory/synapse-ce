package finding

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewManual(t *testing.T) {
	now := time.Unix(0, 0).UTC()

	f, err := NewManual("f1", "e1", ManualInput{Title: "  XSS  ", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Title != "XSS" || f.Kind != KindManual || f.Status != StatusOpen || f.DedupKey != "manual:f1" || f.Version != 1 {
		t.Errorf("unexpected manual finding: %+v", f)
	}
	if f.Priority != 1 {
		t.Errorf("high severity should map to priority 1, got %d", f.Priority)
	}

	if _, err := NewManual("f2", "e1", ManualInput{Title: "   "}, now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("blank title: want ErrValidation, got %v", err)
	}
	if f3, _ := NewManual("f3", "e1", ManualInput{Title: "x"}, now); f3.Severity != shared.SeverityUnknown {
		t.Errorf("default severity = %q, want unknown", f3.Severity)
	}
	if _, err := NewManual("f4", "e1", ManualInput{Title: "x", Severity: shared.Severity("bogus")}, now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad severity: want ErrValidation, got %v", err)
	}
}

func TestNewComment(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	c, err := NewComment("c1", "e1", "f1", "alice", "  hi  ", now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Body != "hi" || c.Author != "alice" {
		t.Errorf("unexpected comment: %+v", c)
	}
	if _, err := NewComment("c2", "e1", "f1", "alice", "   ", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty body: want ErrValidation, got %v", err)
	}
	if _, err := NewComment("c3", "e1", "f1", "  ", "hi", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("blank author: want ErrValidation, got %v", err)
	}
}
