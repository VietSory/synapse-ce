package evidence

import (
	"errors"
	"testing"
)

func chain() []Evidence {
	e1 := Evidence{Kind: "scan", Content: []byte("scan-a")}.Seal()
	e2 := Evidence{Kind: "finding", Content: []byte("finding-b"), PreviousHash: e1.Hash}.Seal()
	e3 := Evidence{Kind: "report", Content: []byte("report-c"), PreviousHash: e2.Hash}.Seal()
	return []Evidence{e1, e2, e3}
}

func TestComputeHashLinksPrevious(t *testing.T) {
	base := Evidence{Kind: "scan", Content: []byte("x")}
	// The same content under a different previous hash yields a different hash.
	a := ComputeHash(base)
	withPrev := base
	withPrev.PreviousHash = "prev"
	if a == ComputeHash(withPrev) {
		t.Error("hash must incorporate the previous hash (chain link)")
	}
	if ComputeHash(base) != ComputeHash(base) {
		t.Error("hash must be deterministic for identical inputs")
	}
}

// TestVerifyChainTamperedAttribution covers the re-audit fix: rewriting WHO produced an
// evidence link (created_by) or WHEN (created_at) breaks the chain, not just content edits.
func TestVerifyChainTamperedAttribution(t *testing.T) {
	c := chain()
	c[1].CreatedBy = "attacker" // rewrite attribution without re-sealing
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for rewritten created_by, got %v", err)
	}
	c = chain()
	c[1].CreatedAt = c[1].CreatedAt.Add(48 * 3600 * 1e9) // backdate by 48h
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for rewritten created_at, got %v", err)
	}
}

func TestVerifyChainValid(t *testing.T) {
	if err := VerifyChain(chain()); err != nil {
		t.Fatalf("valid chain failed verification: %v", err)
	}
	if err := VerifyChain(nil); err != nil {
		t.Errorf("empty chain should verify, got %v", err)
	}
}

func TestVerifyChainTamperedContent(t *testing.T) {
	c := chain()
	c[1].Content = []byte("tampered") // edit content without re-sealing
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for tampered content, got %v", err)
	}
}

func TestVerifyChainBrokenLink(t *testing.T) {
	c := chain()
	c[2].PreviousHash = "0000" // break the link to the prior item
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for a broken link, got %v", err)
	}
}

func TestVerifyChainReordered(t *testing.T) {
	c := chain()
	c[1], c[2] = c[2], c[1] // reordering breaks the previous_hash continuity
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for reordered items, got %v", err)
	}
}
