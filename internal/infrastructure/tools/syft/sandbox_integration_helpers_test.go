package syft_test

import (
	"encoding/json"
	"sort"
)

func purlSet(raw []byte) []string {
	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	_ = json.Unmarshal(raw, &doc)
	var out []string
	for _, c := range doc.Components {
		if c.PURL != "" {
			out = append(out, c.PURL)
		}
	}
	sort.Strings(out)
	return out
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
