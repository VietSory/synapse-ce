package projectuc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

type MeasureAvailabilityState string

const (
	AvailabilityAvailable     MeasureAvailabilityState = "available"
	AvailabilityUnavailable   MeasureAvailabilityState = "unavailable"
	AvailabilityNotApplicable MeasureAvailabilityState = "not_applicable"
)

type MeasureCountMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Value        *int                     `json:"value"`
	Reason       *string                  `json:"unavailable_reason"`
}

type MeasureDecimalMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Value        *float64                 `json:"value"`
	Reason       *string                  `json:"unavailable_reason"`
}

type MeasureGradeMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Grade        *string                  `json:"grade"`
	Reason       *string                  `json:"unavailable_reason"`
}

type SizeMeasures struct {
	Files          MeasureCountMetric   `json:"files"`
	NCLOC          MeasureCountMetric   `json:"ncloc"`
	CommentLines   MeasureCountMetric   `json:"comment_lines"`
	BlankLines     MeasureCountMetric   `json:"blank_lines"`
	Functions      MeasureCountMetric   `json:"functions"`
	CommentDensity MeasureDecimalMetric `json:"comment_density"`
}

type ComplexityMeasures struct {
	Cyclomatic MeasureCountMetric `json:"cyclomatic"`
	Cognitive  MeasureCountMetric `json:"cognitive"`
}

type CoverageMeasures struct {
	CoveredLines    MeasureCountMetric   `json:"covered_lines"`
	CoverableLines  MeasureCountMetric   `json:"coverable_lines"`
	Coverage        MeasureDecimalMetric `json:"coverage"`
	NewCodeCoverage MeasureDecimalMetric `json:"new_code_coverage"`
}

type DuplicationMeasures struct {
	DuplicatedLines    MeasureCountMetric   `json:"duplicated_lines"`
	DuplicationBlocks  MeasureCountMetric   `json:"duplication_blocks"`
	DuplicationDensity MeasureDecimalMetric `json:"duplication_density"`
}

type IssueMeasures struct {
	ByType     map[string]MeasureCountMetric `json:"by_type"`
	BySeverity map[string]MeasureCountMetric `json:"by_severity"`
}

type DebtMeasures struct {
	RemediationEffortMinutes MeasureCountMetric `json:"remediation_effort_minutes"`
}

type RatingsMeasures struct {
	Security        MeasureGradeMetric `json:"security"`
	Reliability     MeasureGradeMetric `json:"reliability"`
	Maintainability MeasureGradeMetric `json:"maintainability"`
}

type ProjectNodeInfo struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type AnalysisMetadata struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	SourceRef    string    `json:"source_ref,omitempty"`
	SourceCommit string    `json:"source_commit,omitempty"`
}

type MeasureNode struct {
	Path        string               `json:"path"`
	Name        string               `json:"name"`
	Kind        measure.NodeKind     `json:"kind"`
	Language    string               `json:"language,omitempty"`
	Size        *SizeMeasures        `json:"size,omitempty"`
	Complexity  *ComplexityMeasures  `json:"complexity,omitempty"`
	Coverage    *CoverageMeasures    `json:"coverage,omitempty"`
	Duplication *DuplicationMeasures `json:"duplication,omitempty"`
	Issues      *IssueMeasures       `json:"issues,omitempty"`
	Debt        *DebtMeasures        `json:"debt,omitempty"`
	Ratings     *RatingsMeasures     `json:"ratings,omitempty"`
}

type ChildCollection struct {
	Items      []MeasureNode `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

type ProjectMeasureResponse struct {
	State           string            `json:"state"` // "analyzed", "not_analyzed"
	Project         ProjectNodeInfo   `json:"project"`
	Analysis        *AnalysisMetadata `json:"analysis"`
	Path            string            `json:"path"`
	IncludedDomains []string          `json:"included_domains"`
	Node            *MeasureNode      `json:"node"`
	Children        ChildCollection   `json:"children"`
}

// MeasureCursor is the opaque pagination token
type MeasureCursor struct {
	Version       int    `json:"v"`
	AnalysisID    string `json:"a"`
	Path          string `json:"r"`
	LastKindRank  int    `json:"k"`
	LastChildPath string `json:"l"`
}

type signedCursor struct {
	Payload   MeasureCursor `json:"p"`
	Signature string        `json:"s"` // base64 string of HMAC-SHA256
}

func (c *MeasureCursor) Encode(secret []byte) string {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	sc := signedCursor{
		Payload:   *c,
		Signature: signature,
	}
	sb, _ := json.Marshal(sc)
	return base64.RawURLEncoding.EncodeToString(sb)
}

func DecodeMeasureCursor(s string, secret []byte) (*MeasureCursor, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	var sc signedCursor
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("invalid cursor json: %w", err)
	}

	if sc.Payload.Version != 1 {
		return nil, fmt.Errorf("unsupported cursor version: %d", sc.Payload.Version)
	}
	if sc.Payload.AnalysisID == "" {
		return nil, errors.New("missing analysis identity in cursor")
	}
	if sc.Payload.LastKindRank != 1 && sc.Payload.LastKindRank != 2 {
		return nil, errors.New("invalid cursor kind rank")
	}

	// Verify signature
	pb, _ := json.Marshal(sc.Payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write(pb)
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sc.Signature), []byte(expectedSignature)) != 1 {
		return nil, errors.New("invalid cursor signature")
	}

	return &sc.Payload, nil
}
