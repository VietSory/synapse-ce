package httpapi

import (
	"net/http"
	"sort"
	"strings"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// agentReadinessResponse is a read-only operator guide for the Agent tab. It does not grant
// authority or execute anything; it only explains which governed workflows can be started from
// the current engagement state and what must be configured first.
type agentReadinessResponse struct {
	Overall        string                   `json:"overall"` // ready | partial | blocked
	Items          []agentReadinessItem     `json:"items"`
	Workflows      []agentWorkflowReadiness `json:"workflows"`
	SuggestedGoals []string                 `json:"suggested_goals"`
	TargetKinds    []engdom.TargetKind      `json:"target_kinds"`
}

type agentReadinessItem struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	OK       bool   `json:"ok"`
	Blocking bool   `json:"blocking"`
	Detail   string `json:"detail"`
	Action   string `json:"action,omitempty"`
}

type agentWorkflowReadiness struct {
	ID            string   `json:"id"`
	Label         string   `json:"label"`
	Description   string   `json:"description"`
	Ready         bool     `json:"ready"`
	Blockers      []string `json:"blockers,omitempty"`
	SuggestedGoal string   `json:"suggested_goal"`
}

// agentReadiness returns a static-analysis-grade workflow preflight for Synapse's agent:
// recon, SCA/SAST analysis, DAST planning, and attack-path hypothesis. This intentionally stays
// read-only and advisory; the actual run still goes through the typed orchestrator, safety gate,
// HITL approvals, and evidence/Judgment lifecycle.
func (rt *Router) agentReadiness(w http.ResponseWriter, r *http.Request) {
	e, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	resp := buildAgentReadiness(e, rt.agent != nil, rt.recon != nil, rt.sca != nil, rt.judgments != nil, rt.threatModels != nil, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

func buildAgentReadiness(e *engdom.Engagement, agentEnabled, reconWired, scaWired, judgmentsWired, threatModelWired bool, now time.Time) agentReadinessResponse {
	kinds := targetKinds(e.Scope.InScope)
	hasRuntime := hasAnyKind(kinds, engdom.TargetDomain, engdom.TargetURL, engdom.TargetIP, engdom.TargetCIDR)
	hasURL := hasAnyKind(kinds, engdom.TargetURL)
	hasRepo := hasAnyKind(kinds, engdom.TargetRepo)
	hasScope := len(e.Scope.InScope) > 0
	windowConfigured := e.AuthorizedFrom != nil || e.AuthorizedTo != nil
	windowOpen := e.IsAuthorizedAt(now)
	allowsExec := e.AllowsExecution()

	items := []agentReadinessItem{
		{
			ID: "agent-enabled", Label: "AI agent enabled", OK: agentEnabled, Blocking: !agentEnabled,
			Detail: boolDetail(agentEnabled, "Agent endpoints are wired for this deployment.", "SYNAPSE_AGENT_ENABLED is off or the agent was not wired at startup."),
			Action: missingAction(agentEnabled, "Enable SYNAPSE_AGENT_ENABLED and configure SYNAPSE_LLM_MODEL / SYNAPSE_LLM_API_KEY, then restart the API."),
		},
		{
			ID: "scope", Label: "Engagement scope", OK: hasScope, Blocking: !hasScope,
			Detail: boolDetail(hasScope, "At least one in-scope target is present.", "No in-scope targets are configured."),
			Action: missingAction(hasScope, "Add a repo, domain, URL, IP, or CIDR target to the engagement scope."),
		},
		{
			ID: "authorization-window", Label: "Authorization window open", OK: windowOpen, Blocking: !windowOpen,
			Detail: windowDetail(e, windowConfigured, windowOpen),
			Action: missingAction(windowOpen, "Set or adjust the authorization window before running governed actions."),
		},
		{
			ID: "lifecycle", Label: "Engagement can execute", OK: allowsExec, Blocking: !allowsExec,
			Detail: boolDetail(allowsExec, "The engagement is not completed or archived.", "Completed/archived engagements cannot run tools."),
			Action: missingAction(allowsExec, "Move work to a draft/active engagement before running tools."),
		},
		{
			ID: "live-recon", Label: "Live recon opt-in", OK: e.LiveReconEnabled, Blocking: false,
			Detail: boolDetail(e.LiveReconEnabled, "Live recon is enabled for this engagement.", "Live recon is disabled; recon/DAST actions will be denied by policy."),
			Action: missingAction(e.LiveReconEnabled, "Enable live recon only after confirming written authorization and the AUP attestation."),
		},
		{
			ID: "analysis-brain", Label: "Judgment lifecycle", OK: judgmentsWired, Blocking: false,
			Detail: boolDetail(judgmentsWired, "Judgment propose/verify routes are available.", "Judgments are not wired; AI analysis can still chat but cannot promote verified AppSec claims."),
			Action: missingAction(judgmentsWired, "Enable SYNAPSE_JUDGMENTS_ENABLED for reachability, critique, threat, and VEX-justification workflows."),
		},
		{
			ID: "threat-model", Label: "Threat-model surface", OK: threatModelWired, Blocking: false,
			Detail: boolDetail(threatModelWired, "Threat-model ingest/read routes are available.", "Threat-model routes are not wired; STRIDE workflow will be advisory only."),
			Action: missingAction(threatModelWired, "Enable the threat-model service when running design-time OWASP/Insecure Design analysis."),
		},
	}

	workflows := []agentWorkflowReadiness{
		workflow("recon", "Recon workflow", "Enumerate and probe in-scope external assets through gated recon tools.",
			"enumerate in-scope web assets, probe HTTP services, and summarize evidence",
			blockers(
				!agentEnabled, "agent is disabled",
				!hasRuntime, "scope needs a domain, URL, IP, or CIDR target",
				!windowOpen, "authorization window is not currently open",
				!allowsExec, "engagement lifecycle does not allow execution",
				!e.LiveReconEnabled, "live recon is disabled",
				!reconWired, "recon service is not wired",
			)),
		workflow("sca-reachability", "SCA reachability workflow", "Use SBOM/SCA results, dependency paths, and Judgment review to reduce false positives.",
			"review dependency findings, propose reachability triage, and identify VEX candidates",
			blockers(
				!agentEnabled, "agent is disabled",
				!hasRepo, "scope needs a repo/local source target",
				!scaWired, "SCA service is not wired",
				!judgmentsWired, "Judgment lifecycle is not enabled",
			)),
		workflow("sast-review", "SAST review workflow", "Review first-party source findings as propose-only AppSec judgments.",
			"review first-party SAST candidates, map them to CWE/OWASP, and list evidence gaps",
			blockers(
				!agentEnabled, "agent is disabled",
				!hasRepo, "scope needs a repo/local source target",
				!scaWired, "scan pipeline is not wired",
				!judgmentsWired, "Judgment lifecycle is not enabled",
			)),
		workflow("dast-planning", "DAST planning workflow", "Draft a passive/low-risk runtime-testing plan for human execution; there is no DAST runtime executor yet, so this proposes a plan only and never runs probes.",
			"create a safe DAST plan for the in-scope URL, starting with passive crawl and non-mutating checks",
			blockers(
				!agentEnabled, "agent is disabled",
				!hasURL, "scope needs a URL target for runtime DAST planning",
				!windowOpen, "authorization window is not currently open",
				!allowsExec, "engagement lifecycle does not allow execution",
				!e.LiveReconEnabled, "live recon is disabled for runtime probes",
			)),
		workflow("attack-path", "Attack-path workflow", "Correlate existing findings into a human-verified attack-chain hypothesis.",
			"review existing findings and propose any plausible attack-chain hypothesis with evidence gaps",
			blockers(
				!agentEnabled, "agent is disabled",
				!judgmentsWired, "Judgment lifecycle is not enabled",
			)),
	}

	suggestions := make([]string, 0, len(workflows))
	for _, wf := range workflows {
		if wf.Ready {
			suggestions = append(suggestions, wf.SuggestedGoal)
		}
	}
	if len(suggestions) == 0 {
		suggestions = append(suggestions, "explain what is missing before an AppSec agent workflow can run")
	}
	overall := "ready"
	for _, it := range items {
		if !it.OK && it.Blocking {
			overall = "blocked"
			break
		}
		if !it.OK {
			overall = "partial"
		}
	}
	if overall != "blocked" {
		readyCount := 0
		for _, wf := range workflows {
			if wf.Ready {
				readyCount++
			}
		}
		if readyCount == 0 {
			overall = "partial"
		}
	}

	return agentReadinessResponse{Overall: overall, Items: items, Workflows: workflows, SuggestedGoals: suggestions, TargetKinds: kinds}
}

func workflow(id, label, desc, goal string, blockers []string) agentWorkflowReadiness {
	return agentWorkflowReadiness{ID: id, Label: label, Description: desc, Ready: len(blockers) == 0, Blockers: blockers, SuggestedGoal: goal}
}

func blockers(pairs ...any) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if ok, _ := pairs[i].(bool); ok {
			if msg, _ := pairs[i+1].(string); msg != "" {
				out = append(out, msg)
			}
		}
	}
	return out
}

func targetKinds(ts []engdom.Target) []engdom.TargetKind {
	seen := map[engdom.TargetKind]bool{}
	for _, t := range ts {
		if strings.TrimSpace(t.Value) != "" {
			seen[t.Kind] = true
		}
	}
	out := make([]engdom.TargetKind, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hasAnyKind(kinds []engdom.TargetKind, wants ...engdom.TargetKind) bool {
	for _, k := range kinds {
		for _, want := range wants {
			if k == want {
				return true
			}
		}
	}
	return false
}

func boolDetail(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func missingAction(ok bool, action string) string {
	if ok {
		return ""
	}
	return action
}

func windowDetail(e *engdom.Engagement, configured, open bool) string {
	if open && !configured {
		return "No authorization bounds are set; the window is open-ended. Add bounds for client work."
	}
	if open {
		return "The current time is inside the authorization window."
	}
	return "The current time is outside the authorization window."
}
