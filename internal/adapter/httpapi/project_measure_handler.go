package httpapi

import (
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (rt *Router) getProjectMeasures(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}

	pathParam := r.URL.Query().Get("path") // "" is allowed and implies root

	res, err := rt.projects.GetMeasures(r.Context(), TenantFrom(r.Context()), key, pathParam)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	writeJSON(w, http.StatusOK, res)
}
