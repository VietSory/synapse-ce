package httpapi

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

const (
	projectSourcePublishMediaType   = "application/x-tar"
	projectSourceToolVersionHeader = "X-Synapse-Tool-Version"
	// The artifact store has lower retained-content caps. This transport ceiling is deliberately
	// independent and slightly generous so tar headers/padding fit while malicious streams cannot
	// make the server read an unbounded body made entirely of ignored paths.
	projectSourcePublishMaxBody = int64(160 << 20)
)

type projectSourcePublisher interface {
	PublishSource(context.Context, projectuc.PublishSourceInput) (projectanalysis.SourceManifest, error)
}

func (rt *Router) publishProjectSource(w http.ResponseWriter, r *http.Request) {
	publisher, ok := rt.projects.(projectSourcePublisher)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, errorBody{Error: "source publication is not configured"})
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != projectSourcePublishMediaType {
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "Content-Type must be application/x-tar"})
		return
	}
	toolVersion := strings.TrimSpace(r.Header.Get(projectSourceToolVersionHeader))
	if toolVersion == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: projectSourceToolVersionHeader + " is required"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, projectSourcePublishMaxBody)
	defer func() { _ = body.Close() }()
	manifest, err := publisher.PublishSource(r.Context(), projectuc.PublishSourceInput{
		TenantID:    shared.ID(TenantFrom(r.Context())),
		ProjectKey:  r.PathValue("key"),
		AnalysisID:  r.PathValue("id"),
		Actor:       PrincipalFrom(r.Context()),
		ToolVersion: toolVersion,
		Archive:     body,
	})
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "source archive exceeds upload limit"})
			return
		}
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, manifest)
}
