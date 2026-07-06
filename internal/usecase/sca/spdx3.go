package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SPDX 3.0.1 minimal JSON-LD projection (CRA-aligned target format) of the stored
// SBOM — core + software profiles. A pure, deterministic function of the stored
// data: sorted components, content-hashed IRIs, the timestamp pinned
// to the scan (never time.Now), so the bytes are byte-reproducible.
const (
	spdx3Context     = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	spdx3SpecVersion = "3.0.1"
	spdx3IRIBase     = "urn:synapse:spdx:"
)

type spdx3Doc struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

type spdx3CreationInfo struct {
	Type        string   `json:"type"`
	ID          string   `json:"@id"`
	SpecVersion string   `json:"specVersion"`
	Created     string   `json:"created"`
	CreatedBy   []string `json:"createdBy"`
}

type spdx3Document struct {
	Type               string   `json:"type"`
	SpdxID             string   `json:"spdxId"`
	CreationInfo       string   `json:"creationInfo"`
	Name               string   `json:"name"`
	ProfileConformance []string `json:"profileConformance"`
	RootElement        []string `json:"rootElement"`
	Element            []string `json:"element"`
}

type spdx3Package struct {
	Type           string `json:"type"`
	SpdxID         string `json:"spdxId"`
	CreationInfo   string `json:"creationInfo"`
	Name           string `json:"name"`
	PackageVersion string `json:"software_packageVersion,omitempty"`
	PackageURL     string `json:"software_packageUrl,omitempty"`
	CopyrightText  string `json:"software_copyrightText"`
}

type spdx3Relationship struct {
	Type             string   `json:"type"`
	SpdxID           string   `json:"spdxId"`
	CreationInfo     string   `json:"creationInfo"`
	From             string   `json:"from"`
	RelationshipType string   `json:"relationshipType"`
	To               []string `json:"to"`
}

// SPDX3 returns the engagement's latest scan SBOM as a deterministic SPDX 3.0.1
// JSON-LD document. shared.ErrNotFound if no scan has run.
func (s *Service) SPDX3(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	data, err := s.LatestResult(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	var res ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	doc := buildSPDX3(res.SBOM, res.Target, res.scanTime())
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal spdx3: %w", err)
	}
	return out, nil
}

func buildSPDX3(doc *sbom.SBOM, target string, created time.Time) spdx3Doc {
	name := target
	if name == "" {
		name = "synapse-sbom"
	}
	const ciID = "_:creationInfo"
	ci := spdx3CreationInfo{
		Type:        "CreationInfo",
		ID:          ciID,
		SpecVersion: spdx3SpecVersion,
		Created:     created.Format(time.RFC3339),
		CreatedBy:   []string{spdx3IRIBase + "agent:synapse"},
	}
	docID := spdx3IRIBase + "doc:" + spdxSlug(name) + "-" + hash12(name+created.Format(time.RFC3339))

	graph := []any{ci}

	var pkgIDs []string
	var pkgs []any
	if doc != nil {
		comps := append([]sbom.Component(nil), doc.Components...)
		sort.SliceStable(comps, func(i, j int) bool {
			if comps[i].Name != comps[j].Name {
				return comps[i].Name < comps[j].Name
			}
			return comps[i].Version < comps[j].Version
		})
		for i, c := range comps {
			id := spdx3IRIBase + "pkg:" + fmt.Sprintf("%d-%s", i, hash12(c.Name+"@"+c.Version+c.PURL))
			pkgIDs = append(pkgIDs, id)
			pkgs = append(pkgs, spdx3Package{
				Type:           "software_Package",
				SpdxID:         id,
				CreationInfo:   ciID,
				Name:           c.Name,
				PackageVersion: c.Version,
				PackageURL:     c.PURL,
				CopyrightText:  "NOASSERTION",
			})
		}
	}

	graph = append(graph, spdx3Document{
		Type:               "SpdxDocument",
		SpdxID:             docID,
		CreationInfo:       ciID,
		Name:               name,
		ProfileConformance: []string{"core", "software"},
		RootElement:        pkgIDs,
		Element:            pkgIDs,
	})
	graph = append(graph, pkgs...)
	if len(pkgIDs) > 0 {
		graph = append(graph, spdx3Relationship{
			Type:             "Relationship",
			SpdxID:           spdx3IRIBase + "rel:contains",
			CreationInfo:     ciID,
			From:             docID,
			RelationshipType: "contains",
			To:               pkgIDs,
		})
	}

	return spdx3Doc{Context: spdx3Context, Graph: graph}
}
