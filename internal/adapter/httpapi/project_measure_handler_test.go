package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type mockMeasureService struct {
	projectService
	err error
	res projectuc.ProjectMeasureResponse
}

func (m mockMeasureService) GetMeasures(_ context.Context, _, _, _ string) (projectuc.ProjectMeasureResponse, error) {
	return m.res, m.err
}

func TestGetProjectMeasures(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		pathParam  string
		svcErr     error
		wantStatus int
	}{
		{
			name:       "success root",
			key:        "demo",
			pathParam:  "",
			svcErr:     nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "success path",
			key:        "demo",
			pathParam:  "src",
			svcErr:     nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing key",
			key:        "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "not found",
			key:        "demo",
			pathParam:  "missing",
			svcErr:     shared.ErrNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "internal error",
			key:        "demo",
			svcErr:     errors.New("db error"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := mockMeasureService{err: tt.svcErr, res: projectuc.ProjectMeasureResponse{
				Component: measure.Node{Path: tt.pathParam},
			}}

			rt := &Router{log: discardLog(), projects: &svc}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+tt.key+"/measures", nil)
			if tt.key != "" {
				req.SetPathValue("key", tt.key)
			}
			if tt.pathParam != "" {
				q := req.URL.Query()
				q.Add("path", tt.pathParam)
				req.URL.RawQuery = q.Encode()
			}
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))

			rr := httptest.NewRecorder()
			rt.getProjectMeasures(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %v, want %v", rr.Code, tt.wantStatus)
			}
		})
	}
}
