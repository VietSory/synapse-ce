package export

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	infoURI      = "https://github.com/KKloudTarus/synapse-ce"
)

// SARIF 2.1.0 subset (the fields Synapse emits).

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string       `json:"id"`
	ShortDescription     SARIFText    `json:"shortDescription"`
	HelpURI              string       `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFConfig `json:"defaultConfiguration,omitempty"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFText       `json:"message"`
	Locations  []SARIFLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type SARIFLocation struct {
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations"`
}

type SARIFLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

func buildSARIF(findings []finding.Finding, version string) *SARIFLog {
	rules := make([]SARIFRule, 0)
	seen := map[string]bool{}
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		p := parseDedup(f.DedupKey)
		ruleID := p.advisory
		if ruleID == "" {
			ruleID = f.ID.String()
		}
		level := sarifLevel(f.Severity)

		if !seen[ruleID] {
			seen[ruleID] = true
			rule := SARIFRule{
				ID:                   ruleID,
				ShortDescription:     SARIFText{Text: f.Title},
				DefaultConfiguration: &SARIFConfig{Level: level},
			}
			if strings.HasPrefix(p.advisory, "CVE-") {
				rule.HelpURI = "https://nvd.nist.gov/vuln/detail/" + p.advisory
			}
			rules = append(rules, rule)
		}

		res := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFText{Text: f.Title},
			Properties: map[string]any{
				"severity":  string(f.Severity),
				"kev":       f.KEV,
				"riskScore": f.RiskScore,
				"status":    string(f.Status),
			},
		}
		if f.CVSSVector != "" {
			res.Properties["cvssVector"] = f.CVSSVector
		}
		if f.ClassReachability != "" {
			// Coarse JVM class-reachability: "reachable" | "unreferenced". Advisory — lets a
			// consumer separate/deprioritize deps the app never references (priority already reflects it).
			res.Properties["componentReachability"] = f.ClassReachability
		}
		if p.component != "" {
			res.Locations = []SARIFLocation{{
				LogicalLocations: []SARIFLogicalLocation{{Name: p.component + "@" + p.version, Kind: "module"}},
			}}
		}
		results = append(results, res)
	}

	return &SARIFLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "synapse",
				Version:        version,
				InformationURI: infoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}
