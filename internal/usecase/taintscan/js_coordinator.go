package taintscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	jsProposerActor       = "system:javascript-taint-scan"
	maxJSTaintProposals   = 10_000
	maxJSWitnessBytes     = 16 * 1024
	maxJSWitnessFrameSize = 384
	maxJSLocationBytes    = 500
)

// JSCoordinator turns source-only JavaScript/TypeScript semantic facts into proposed CapSAST
// judgments. It is propose-only: partial coverage may support a positive witness, but absence of
// a path never self-confirms a clean result.
type JSCoordinator struct {
	provider ports.JSFactsProvider
	proposer proposer
	catalog  taint.JSCatalog
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.TaintScanner = (*JSCoordinator)(nil)
var _ ports.TaintCoverageScanner = (*JSCoordinator)(nil)

func NewJSCoordinator(provider ports.JSFactsProvider, p proposer, catalog taint.JSCatalog, audit ports.AuditLogger, clock ports.Clock) (*JSCoordinator, error) {
	if provider == nil || p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: javascript taint coordinator is missing a dependency", shared.ErrValidation)
	}
	if len(catalog.Sources) == 0 || len(catalog.Sinks) == 0 {
		return nil, fmt.Errorf("%w: javascript taint coordinator needs a non-empty catalog", shared.ErrValidation)
	}
	return &JSCoordinator{provider: provider, proposer: p, catalog: catalog, audit: audit, clock: clock}, nil
}

func (c *JSCoordinator) Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error) {
	outcome, err := c.ScanWithCoverage(ctx, engagementID, targetRef)
	return outcome.Proposed, err
}

func (c *JSCoordinator) ScanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string) (ports.TaintScanOutcome, error) {
	outcome := ports.TaintScanOutcome{Coverage: ports.AnalysisCoverage{
		Analyzer: "javascript-semantic-taint-v1", Language: "javascript", Status: ports.AnalysisCoverageUnavailable,
	}}
	if ctx == nil || engagementID.IsZero() || strings.TrimSpace(targetRef) == "" {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, fmt.Errorf("%w: javascript taint scan needs context, engagement, and target", shared.ErrValidation)
	}
	document, available, err := c.provider.JSFacts(ctx, targetRef)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonExtractionFailed
		return outcome, fmt.Errorf("javascript taint semantic extraction (no coverage): %w", err)
	}
	if !available {
		outcome.Coverage.Reason = ports.AnalysisReasonSidecarUnavailable
		return outcome, fmt.Errorf("%w: javascript taint semantic sidecar is unavailable", shared.ErrNotFound)
	}
	if err := ctx.Err(); err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, err
	}

	outcome.Coverage.Available = true
	outcome.Coverage.FilesSeen = document.FilesSeen
	outcome.Coverage.FilesParsed = document.FilesParsed
	outcome.Coverage.Symbols = len(document.Symbols)
	outcome.Coverage.Calls = len(document.Calls)
	outcome.Coverage.Values = len(document.Values)
	outcome.Coverage.Flows = len(document.Flows)
	outcome.Coverage.Truncated = document.Truncated
	if document.FilesSeen == 0 {
		outcome.Coverage.Status = ports.AnalysisCoverageNotApplicable
		outcome.Coverage.Reason = ports.AnalysisReasonNoSource
		return outcome, nil
	}

	resolution, err := jsprogram.Resolve(document)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonResolutionFailed
		return outcome, fmt.Errorf("javascript taint semantic resolution (no coverage): %w", err)
	}
	outcome.Coverage.Gaps = jsCoverageGaps(resolution.Gaps)
	outcome.Coverage.Complete = resolution.Complete
	if resolution.Complete {
		outcome.Coverage.Status = ports.AnalysisCoverageComplete
	} else {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
	}

	graph, err := taint.BuildJSValueGraph(document, resolution, c.catalog)
	if err != nil {
		outcome.Coverage.Status = ports.AnalysisCoverageUnavailable
		outcome.Coverage.Complete = false
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, err
	}
	paths := graph.Vulnerabilities()
	paths = append(paths, taint.JSPrototypePollutionPaths(document, resolution, c.catalog, graph)...)
	paths = deduplicateJSTaintPaths(paths)
	outcome.Coverage.Truncated = outcome.Coverage.Truncated || graph.Truncated
	if graph.Truncated {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
		outcome.Coverage.Complete = false
	}
	analysisComplete := resolution.Complete && !graph.Truncated

	proposed := 0
	for _, finding := range paths {
		if err := ctx.Err(); err != nil {
			return degradeJSOutcome(outcome, proposed, ports.AnalysisReasonAnalysisFailed), err
		}
		if proposed >= maxJSTaintProposals {
			return degradeJSOutcome(outcome, proposed, ports.AnalysisReasonProposalBudgetExceeded), fmt.Errorf("%w: javascript taint proposal budget exceeded", shared.ErrValidation)
		}
		claim := judgment.SASTClaim{
			CWE: finding.CWE, Rule: finding.Rule,
			Location: boundedJSLocation(jsPositionLine(finding.SinkPos), finding.Callee),
			DataFlow: jsClaimDataFlow(finding, graph, analysisComplete),
		}
		judged, err := c.proposer.Propose(
			ctx, jsProposerActor, engagementID, judgment.CapSAST, judgment.SubjectDataFlow,
			jsFlowSubjectID(engagementID, finding), claim,
		)
		if err != nil {
			return degradeJSOutcome(outcome, proposed, ports.AnalysisReasonAnalysisFailed), fmt.Errorf("propose javascript taint judgment: %w", err)
		}
		if err := c.recordJSWitness(ctx, engagementID, judged.ID, finding, graph, analysisComplete); err != nil {
			return degradeJSOutcome(outcome, proposed+1, ports.AnalysisReasonAnalysisFailed), err
		}
		proposed++
	}
	outcome.Proposed = proposed
	outcome.Coverage.Proposals = proposed
	return outcome, nil
}

func degradeJSOutcome(outcome ports.TaintScanOutcome, proposed int, reason ports.AnalysisCoverageReason) ports.TaintScanOutcome {
	outcome.Proposed = proposed
	outcome.Coverage.Proposals = proposed
	outcome.Coverage.Status = ports.AnalysisCoveragePartial
	outcome.Coverage.Complete = false
	outcome.Coverage.Reason = reason
	return outcome
}

func jsClaimDataFlow(finding taint.JSTaintPath, graph taint.JSValueFlowGraph, complete bool) *judgment.SASTDataFlow {
	source, ok := jsFlowLocation(finding.SourcePos)
	if !ok { return nil }
	sink, ok := jsFlowLocation(finding.SinkPos)
	if !ok { return nil }
	steps := make([]judgment.SASTFlowLocation, 0, min(len(finding.Path)+2, judgment.MaxSASTDataFlowSteps))
	appendStep := func(location judgment.SASTFlowLocation) {
		if len(steps) == 0 || steps[len(steps)-1] != location { steps = append(steps, location) }
	}
	appendStep(source)
	for _, valueID := range finding.Path {
		location, exists := jsFlowLocation(graph.Positions[valueID])
		if !exists || len(steps) >= judgment.MaxSASTDataFlowSteps-1 { continue }
		appendStep(location)
	}
	if len(steps) == judgment.MaxSASTDataFlowSteps && steps[len(steps)-1] != sink {
		steps[len(steps)-1] = sink
	} else {
		appendStep(sink)
	}
	return &judgment.SASTDataFlow{
		Language: "javascript", Source: source, Sink: sink, Steps: steps,
		CoverageComplete: complete, GraphTruncated: graph.Truncated,
	}
}

func jsFlowLocation(pos jsprogram.Position) (judgment.SASTFlowLocation, bool) {
	if pos.File == "" || len(pos.File) > maxJSLocationBytes || pos.Line <= 0 || pos.Column < 0 {
		return judgment.SASTFlowLocation{}, false
	}
	return judgment.SASTFlowLocation{File: pos.File, Line: pos.Line, Column: pos.Column}, true
}

func jsCoverageGaps(gaps []jsprogram.CoverageGap) []ports.AnalysisCoverageGap {
	counts := map[string]int{}
	for _, gap := range gaps { if gap.Kind != "" { counts[string(gap.Kind)]++ } }
	kinds := make([]string, 0, len(counts))
	for kind := range counts { kinds = append(kinds, kind) }
	sort.Strings(kinds)
	out := make([]ports.AnalysisCoverageGap, 0, len(kinds))
	for _, kind := range kinds { out = append(out, ports.AnalysisCoverageGap{Kind: kind, Count: counts[kind]}) }
	return out
}

func deduplicateJSTaintPaths(paths []taint.JSTaintPath) []taint.JSTaintPath {
	paths = append([]taint.JSTaintPath(nil), paths...)
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Path) != len(paths[j].Path) { return len(paths[i].Path) < len(paths[j].Path) }
		left := string(paths[i].Class)+"\x00"+paths[i].Rule+"\x00"+paths[i].CallID+"\x00"+paths[i].SourceID
		right := string(paths[j].Class)+"\x00"+paths[j].Rule+"\x00"+paths[j].CallID+"\x00"+paths[j].SourceID
		return left < right
	})
	seen := map[string]bool{}
	out := make([]taint.JSTaintPath, 0, len(paths))
	for _, item := range paths {
		key := item.CallID+"\x00"+string(item.Class)+"\x00"+item.Rule
		if seen[key] { continue }
		seen[key] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].CallID+"\x00"+string(out[i].Class)+"\x00"+out[i].Rule
		right := out[j].CallID+"\x00"+string(out[j].Class)+"\x00"+out[j].Rule
		return left < right
	})
	return out
}

func jsFlowSubjectID(engagementID shared.ID, finding taint.JSTaintPath) shared.ID {
	key := engagementID.String()+"|javascript-taint-v1|"+finding.CallID+"|"+string(finding.Class)+"|"+finding.Rule
	sum := sha256.Sum256([]byte(key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

func (c *JSCoordinator) recordJSWitness(ctx context.Context, engagementID, judgmentID shared.ID, finding taint.JSTaintPath, graph taint.JSValueFlowGraph, complete bool) error {
	metadata := map[string]string{
		"engagement": engagementID.String(), "language": "javascript", "class": string(finding.Class),
		"cwe": finding.CWE, "rule": finding.Rule, "callee": boundedJSUTF8(finding.Callee, maxJSWitnessFrameSize),
		"path": jsWitnessPath(finding.Path, graph.Positions), "coverage_complete": strconv.FormatBool(complete),
		"graph_truncated": strconv.FormatBool(graph.Truncated),
	}
	if source := jsPositionString(finding.SourcePos); source != "" { metadata["source_pos"] = boundedJSUTF8(source, maxJSWitnessFrameSize) }
	if sink := jsPositionString(finding.SinkPos); sink != "" { metadata["sink_pos"] = boundedJSUTF8(sink, maxJSWitnessFrameSize) }
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor: jsProposerActor, Action: "judgment.javascript_taint_proposed", Target: judgmentID.String(), Metadata: metadata, At: c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit javascript taint proposal: %w", err)
	}
	return nil
}

func jsWitnessPath(values []string, positions map[string]jsprogram.Position) string {
	frames := make([]string, 0, min(len(values), maxWitnessElems))
	bytes := 0
	for index, valueID := range values {
		if index >= maxWitnessElems { frames = append(frames, "… (frame limit)"); break }
		frame := jsPositionString(positions[valueID])
		if frame == "" {
			sum := sha256.Sum256([]byte(valueID))
			frame = "value:"+hex.EncodeToString(sum[:6])
		}
		frame = boundedJSUTF8(frame, maxJSWitnessFrameSize)
		additional := len(frame)
		if len(frames) > 0 { additional += len(" → ") }
		if bytes+additional > maxJSWitnessBytes { frames = append(frames, "… (byte limit)"); break }
		frames = append(frames, frame)
		bytes += additional
	}
	return boundedJSUTF8(strings.Join(frames, " → "), maxJSWitnessBytes)
}

func jsPositionLine(pos jsprogram.Position) string {
	if pos.File == "" || pos.Line <= 0 { return "" }
	return pos.File+":"+strconv.Itoa(pos.Line)
}

func jsPositionString(pos jsprogram.Position) string {
	if pos.File == "" || pos.Line <= 0 || pos.Column < 0 { return "" }
	return pos.File+":"+strconv.Itoa(pos.Line)+":"+strconv.Itoa(pos.Column)
}

func boundedJSLocation(location, fallback string) string {
	if strings.TrimSpace(location) == "" { location = fallback }
	if strings.TrimSpace(location) == "" { location = "javascript-call" }
	return boundedJSUTF8(location, maxJSLocationBytes)
}

func boundedJSUTF8(value string, limit int) string {
	if limit <= 0 { return "" }
	value = strings.ToValidUTF8(value, "")
	if len(value) <= limit { return value }
	value = value[:limit]
	for len(value) > 0 && !utf8.ValidString(value) { value = value[:len(value)-1] }
	return value
}
