package jsresolve

import (
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxResolverModules         = 200000
	defaultMaxResolverEdges           = 1000000
	defaultMaxResolverGraphCoverage   = 200000
	defaultMaxResolverBindingsPerEdge = 4096
	defaultMaxResolverSpecifierBytes  = 4096
	defaultMaxResolverModulePathBytes = 32768
	defaultMaxResolverAliasWork       = 1000000
	defaultMaxResolverCandidates      = 256
	defaultMaxResolverCoverage        = 4096
)

type resolverLimits struct {
	maxModules         int
	maxEdges           int
	maxGraphCoverage   int
	maxBindingsPerEdge int
	maxSpecifierBytes  int
	maxModulePathBytes int
	maxAliasWork       int
	maxCandidates      int
	maxCoverageIssues  int
}

func defaultResolverLimits() resolverLimits {
	return resolverLimits{
		maxModules:         defaultMaxResolverModules,
		maxEdges:           defaultMaxResolverEdges,
		maxGraphCoverage:   defaultMaxResolverGraphCoverage,
		maxBindingsPerEdge: defaultMaxResolverBindingsPerEdge,
		maxSpecifierBytes:  defaultMaxResolverSpecifierBytes,
		maxModulePathBytes: defaultMaxResolverModulePathBytes,
		maxAliasWork:       defaultMaxResolverAliasWork,
		maxCandidates:      defaultMaxResolverCandidates,
		maxCoverageIssues:  defaultMaxResolverCoverage,
	}
}

func (l resolverLimits) validate() error {
	if l.maxModules <= 0 || l.maxEdges <= 0 || l.maxGraphCoverage <= 0 || l.maxBindingsPerEdge <= 0 ||
		l.maxSpecifierBytes <= 0 || l.maxModulePathBytes <= 0 || l.maxAliasWork <= 0 || l.maxCandidates <= 0 || l.maxCoverageIssues <= 0 {
		return fmt.Errorf("%w: resolver limits must be positive", shared.ErrValidation)
	}
	return nil
}

// Resolver resolves source module specifiers to built-in, local, workspace, or
// package-root identities. R2B deliberately leaves third-party SBOM component
// correlation unresolved for R2C.
type Resolver struct {
	inventory *InventoryBuilder
	aliases   *aliasInventoryBuilder
	limits    resolverLimits
}

// NewResolver returns a bounded, deterministic and offline JS/TS specifier resolver.
func NewResolver() *Resolver {
	return &Resolver{
		inventory: NewInventoryBuilder(),
		aliases:   newAliasInventoryBuilder(),
		limits:    defaultResolverLimits(),
	}
}

func newResolverWithLimits(inventory *InventoryBuilder, aliases *aliasInventoryBuilder, limits resolverLimits) *Resolver {
	return &Resolver{inventory: inventory, aliases: aliases, limits: limits}
}

type resolutionCoverageSink struct {
	issues []jsresolution.CoverageIssue
	limit  int
	capped bool
}

func (s *resolutionCoverageSink) add(issue jsresolution.CoverageIssue) {
	if s.capped {
		return
	}
	if len(s.issues) < s.limit-1 {
		s.issues = append(s.issues, issue)
		return
	}
	budget := jsresolution.CoverageIssue{
		Kind:   jsresolution.CoverageMetadataBudgetExceeded,
		Path:   ".",
		Detail: fmt.Sprintf("resolution coverage issue budget exceeded (%d)", s.limit),
	}
	if len(s.issues) < s.limit {
		s.issues = append(s.issues, budget)
	} else {
		s.issues[s.limit-1] = budget
	}
	s.capped = true
}

func (s *resolutionCoverageSink) addAll(issues []jsresolution.CoverageIssue) {
	for _, issue := range issues {
		s.add(issue)
		if s.capped {
			return
		}
	}
}

type resolverWorkBudget struct {
	remaining int
	exceeded  bool
	reported  bool
}

func (b *resolverWorkBudget) consume() bool {
	if b == nil {
		return true
	}
	if b.remaining <= 0 {
		b.exceeded = true
		return false
	}
	b.remaining--
	return true
}

func markAliasBudgetExceeded(base jsresolution.ImportResolution, budget *resolverWorkBudget, coverage *resolutionCoverageSink, limit int) jsresolution.ImportResolution {
	base.Status = jsresolution.StatusUnresolved
	base.Package = jsresolution.PackageIdentity{}
	base.Candidates = nil
	base.Reason = "alias resolution work budget exceeded"
	if budget != nil && !budget.reported {
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".",
			Detail: fmt.Sprintf("alias resolution work budget exceeded (%d)", limit),
		})
		budget.reported = true
	}
	return base
}
