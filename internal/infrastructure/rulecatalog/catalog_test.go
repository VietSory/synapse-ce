package rulecatalog_test

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func validRule(key string) rule.Rule {
	return rule.Rule{
		Key:                 rule.Key(key),
		Name:                "Valid Rule",
		Language:            "General",
		Type:                rule.TypeVulnerability,
		Qualities:           []rule.Quality{rule.QualitySecurity},
		DefaultSeverity:     shared.SeverityHigh,
		Tags:                []string{"tag1"},
		CWE:                 []string{"CWE-79"},
		OWASP:               []string{"A1"},
		Description:         "desc",
		Rationale:           "rat",
		Remediation:         "rem",
		CompliantExample:    "comp",
		NoncompliantExample: "noncomp",
		RemediationEffort:   5,
		Detection:           rule.DetectionPattern,
	}
}

func TestCatalogRejectsDuplicateKey(t *testing.T) {
	entries := []rule.Rule{
		validRule("rule-1"),
		validRule("rule-1"),
	}

	_, err := rulecatalog.New(entries)
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestCatalogRejectsInvalidRule(t *testing.T) {
	entry := validRule("rule-1")
	entry.Name = ""

	_, err := rulecatalog.New([]rule.Rule{entry})
	if err == nil {
		t.Fatal("expected invalid rule to be rejected")
	}
}

func TestCatalogListEmpty(t *testing.T) {
	cat, err := rulecatalog.New(nil)
	if err != nil {
		t.Fatalf("New empty catalog: %v", err)
	}

	got, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List empty catalog: %v", err)
	}

	if got == nil {
		t.Fatal("expected non-nil empty slice")
	}

	if len(got) != 0 {
		t.Fatalf("expected zero rules, got %d", len(got))
	}
}

func TestCatalogListSortedByKey(t *testing.T) {
	entries := []rule.Rule{
		validRule("rule-z"),
		validRule("rule-b"),
		validRule("rule-m"),
		validRule("rule-a"),
	}

	cat, err := rulecatalog.New(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if len(res) != 4 {
		t.Fatalf("expected 4, got %d", len(res))
	}

	if res[0].Key != "rule-a" || res[1].Key != "rule-b" || res[2].Key != "rule-m" || res[3].Key != "rule-z" {
		t.Errorf("expected sorted keys, got %v", res)
	}
}

func TestCatalogCopiesInput(t *testing.T) {
	r := validRule("rule-1")
	entries := []rule.Rule{r}

	cat, err := rulecatalog.New(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries[0].Key = "rule-2"
	entries[0].Qualities[0] = rule.QualityReliability
	entries[0].Tags[0] = "mutated-tag"
	entries[0].CWE[0] = "CWE-999"
	entries[0].OWASP[0] = "A99"

	res, err := cat.Get(context.Background(), "rule-1")
	if err != nil {
		t.Fatalf("Get rule-1: %v", err)
	}

	if res.Tags[0] == "mutated-tag" || res.Qualities[0] == rule.QualityReliability || res.CWE[0] == "CWE-999" || res.OWASP[0] == "A99" {
		t.Error("catalog mutated when input was mutated")
	}
}

func TestCatalogReturnsCopies(t *testing.T) {
	entries := []rule.Rule{validRule("rule-1")}
	cat, err := rulecatalog.New(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res, err := cat.Get(context.Background(), "rule-1")
	if err != nil {
		t.Fatalf("Get rule-1: %v", err)
	}
	res.Qualities[0] = rule.QualityReliability
	res.Tags[0] = "mutated-tag"
	res.CWE[0] = "CWE-999"
	res.OWASP[0] = "A99"

	res2, err := cat.Get(context.Background(), "rule-1")
	if err != nil {
		t.Fatalf("Get rule-1: %v", err)
	}
	if res2.Tags[0] == "mutated-tag" || res2.Qualities[0] == rule.QualityReliability || res2.CWE[0] == "CWE-999" || res2.OWASP[0] == "A99" {
		t.Error("catalog mutated when returned value was mutated")
	}

	listRes, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	listRes[0].Qualities[0] = rule.QualityReliability
	listRes[0].Tags[0] = "mutated-again"
	listRes[0].CWE[0] = "CWE-999"
	listRes[0].OWASP[0] = "A99"

	listRes2, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if listRes2[0].Tags[0] == "mutated-again" || listRes2[0].Qualities[0] == rule.QualityReliability || listRes2[0].CWE[0] == "CWE-999" || listRes2[0].OWASP[0] == "A99" {
		t.Error("catalog mutated when returned list was mutated")
	}
}

func TestCatalogContextCancellation(t *testing.T) {
	cat, err := rulecatalog.New([]rule.Rule{validRule("rule-1")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cat.List(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("List expected context.Canceled, got %v", err)
	}

	_, err = cat.Get(ctx, "rule-1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Get expected context.Canceled, got %v", err)
	}
}

func TestCatalogGetMissing(t *testing.T) {
	cat, err := rulecatalog.New([]rule.Rule{validRule("rule-1")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = cat.Get(context.Background(), "missing")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
