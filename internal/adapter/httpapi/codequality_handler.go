package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
)

// codeQualityReportView wraps the latest stored code-quality report with an availability flag.
type codeQualityReportView struct {
	Available bool                `json:"available"`
	Reason    string              `json:"reason,omitempty"`
	Report    *codequality.Report `json:"report,omitempty"`
}

const codeQualityUnavailable = "Run an Engagement scan with Code quality enabled to generate a stored report"

// codeQualityReport returns the code-quality report stored by the latest explicit Engagement scan. Auth
// (PermView) + tenant scoping are applied by the route wrapper. Reading this endpoint never analyzes source.
func (rt *Router) codeQualityReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	if _, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id)); err != nil {
		writeError(w, rt.log, err)
		return
	}
	data, err := rt.sca.LatestResult(r.Context(), shared.ID(id))
	if errors.Is(err, shared.ErrNotFound) {
		writeJSON(w, http.StatusOK, codeQualityReportView{Reason: codeQualityUnavailable})
		return
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var cached struct {
		CodeQuality *codequality.Report `json:"code_quality"`
	}
	if err := json.Unmarshal(data, &cached); err != nil {
		writeError(w, rt.log, fmt.Errorf("decode cached scan result: %w", err))
		return
	}
	if cached.CodeQuality == nil {
		writeJSON(w, http.StatusOK, codeQualityReportView{Reason: codeQualityUnavailable})
		return
	}
	writeJSON(w, http.StatusOK, codeQualityReportView{Available: true, Report: cached.CodeQuality})
}
