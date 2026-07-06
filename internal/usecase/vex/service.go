// Package vex consumes OpenVEX documents (CRA-aligned): a client hands Synapse a
// VEX doc asserting the exploitability status of vulnerabilities in their products,
// and Synapse applies each statement to the matching finding — e.g. not_affected
// suppresses it (false positive), fixed marks it remediated. Every applied change is
// recorded on the append-only audit log. This is the inverse of the
// OpenVEX the export service emits.
package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service applies OpenVEX statements to an engagement's findings.
type Service struct {
	engagements ports.EngagementRepository
	findings    ports.FindingRepository
	audit       ports.AuditLogger
	clock       ports.Clock
}

// NewService validates dependencies and returns the VEX service.
func NewService(engagements ports.EngagementRepository, findings ports.FindingRepository, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if engagements == nil || findings == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: vex service is missing a dependency", shared.ErrValidation)
	}
	return &Service{engagements: engagements, findings: findings, audit: audit, clock: clock}, nil
}

// openVEXDoc is the subset of OpenVEX 0.2 Synapse consumes.
type openVEXDoc struct {
	Context    string `json:"@context"`
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"statements"`
}

// ApplyResult summarizes what an import did.
type ApplyResult struct {
	Statements int `json:"statements"` // statements in the document
	Matched    int `json:"matched"`    // findings a statement matched
	Applied    int `json:"applied"`    // findings whose status actually changed
}

// Apply parses an OpenVEX document and applies each statement to the matching
// findings of the engagement, returning what changed. A statement matches a finding
// by advisory id + component (+ version when the product carries one); the optimistic
// version guards each update.
func (s *Service) Apply(ctx context.Context, actor string, tenantID, engagementID shared.ID, vexJSON []byte) (ApplyResult, error) {
	var doc openVEXDoc
	if err := json.Unmarshal(vexJSON, &doc); err != nil {
		return ApplyResult{}, fmt.Errorf("%w: invalid VEX document: %v", shared.ErrValidation, err)
	}
	if !strings.Contains(doc.Context, "openvex") || len(doc.Statements) == 0 {
		return ApplyResult{}, fmt.Errorf("%w: not a non-empty OpenVEX document", shared.ErrValidation)
	}
	// Confirm the engagement exists AND belongs to the caller's tenant (404 cross-tenant;
	// defense-in-depth behind the withEngTenant route wrapper — parity with SBOM import).
	if _, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID); err != nil {
		return ApplyResult{}, fmt.Errorf("load engagement: %w", err)
	}

	findings, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("load findings: %w", err)
	}

	res := ApplyResult{Statements: len(doc.Statements)}
	for _, st := range doc.Statements {
		target, ok := vexTargetStatus(st.Status)
		if !ok {
			continue // a status we don't map (e.g. unknown) — leave findings untouched
		}
		adv := st.Vulnerability.Name
		for _, p := range st.Products {
			prodComp, prodVer := splitProduct(p.ID)
			for i := range findings {
				f := &findings[i]
				a, comp, ver := parseVulnDedup(f.DedupKey)
				if a != adv || !componentMatches(comp, prodComp) {
					continue
				}
				if prodVer != "" && ver != prodVer {
					continue
				}
				res.Matched++
				if f.Status == target {
					continue // already in the asserted state
				}
				updated, err := s.findings.UpdateStatus(ctx, engagementID, f.ID, target, f.Version)
				if err != nil {
					continue // conflict/not-found: skip this finding, keep applying others
				}
				*f = updated
				res.Applied++
				_ = s.audit.Record(ctx, ports.AuditEntry{
					Actor: actor, Action: "finding.vex", Target: f.ID.String(),
					Metadata: map[string]string{
						"engagement":    engagementID.String(),
						"advisory":      adv,
						"vex_status":    st.Status,
						"new_status":    string(target),
						"justification": st.Justification,
					},
					At: s.clock.Now(),
				})
			}
		}
	}
	return res, nil
}

// vexTargetStatus maps an OpenVEX status to the finding status it implies.
func vexTargetStatus(s string) (finding.Status, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected":
		return finding.StatusFalsePos, true
	case "fixed":
		return finding.StatusRemediated, true
	case "affected":
		return finding.StatusConfirmed, true
	case "under_investigation":
		return finding.StatusTriage, true
	default:
		return "", false
	}
}

// parseVulnDedup extracts (advisory, component, version) from a "vuln:adv:comp:ver"
// dedup key (the SCA finding identity).
func parseVulnDedup(key string) (advisory, component, version string) {
	rest, ok := strings.CutPrefix(key, "vuln:")
	if !ok {
		return "", "", ""
	}
	parts := strings.Split(rest, ":")
	switch {
	case len(parts) >= 3:
		return parts[0], strings.Join(parts[1:len(parts)-1], ":"), parts[len(parts)-1]
	case len(parts) == 2:
		return parts[0], "", parts[1]
	default:
		return rest, "", ""
	}
}

// splitProduct splits an OpenVEX product @id into component + version on the last
// '@' (so a PURL "pkg:npm/foo@1.2.3" yields "pkg:npm/foo" + "1.2.3").
func splitProduct(id string) (component, version string) {
	if i := strings.LastIndex(id, "@"); i > 0 {
		return id[:i], id[i+1:]
	}
	return id, ""
}

// componentMatches reports whether a finding's component matches a VEX product
// component: exact, or the product's PURL package-name segment equals it. Matching
// the path-bounded name (not a raw substring) avoids over-matching — a product
// "pkg:npm/foobar" must NOT match a finding component "foo".
func componentMatches(findingComp, productComp string) bool {
	if findingComp == "" || productComp == "" {
		return false
	}
	return findingComp == productComp || purlName(productComp) == findingComp
}

// purlName returns the package-name segment of a product id (the part after the
// last '/'), so "pkg:npm/lodash" -> "lodash" and "@scope/foo" -> "foo".
func purlName(product string) string {
	if i := strings.LastIndex(product, "/"); i >= 0 {
		return product[i+1:]
	}
	return product
}
